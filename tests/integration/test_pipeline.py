"""Integration tests for end-to-end pipeline orchestration with mocked clients."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from aegis.middleware.models import AegisReport, RagContext, UEBAMetrics, WazuhLog
from aegis.middleware.pipeline import analyze_log, triage_log


class _FakeOllamaClient:
    def __init__(self, responses: dict[str, Any]) -> None:
        self._responses = responses
        self.calls: list[str] = []

    async def generate(
        self,
        model: str,
        prompt: str,
        timeout: float,
        keep_alive: int = 300,
        num_predict: int | None = None,
        format_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = prompt
        _ = timeout
        _ = num_predict
        _ = format_schema
        self.calls.append(model)
        response = self._responses[model]
        if isinstance(response, Exception):
            raise response
        return response


class _FakeChromaDBClient:
    def __init__(self, context: RagContext) -> None:
        self.context = context

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        _ = asset_identifier
        return self.context

    async def record_activity(self, asset_identifier: str, now: float | None = None) -> RagContext:
        _ = (asset_identifier, now)
        return self.context


class _FakeShuffleClient:
    def __init__(self, should_fail: bool = False) -> None:
        self.should_fail = should_fail
        self.reports_sent = 0

    async def send_report(self, report: Any) -> bool:
        _ = report
        self.reports_sent += 1
        if self.should_fail:
            raise RuntimeError("soar down")
        return True


def _make_log(
    rule_level: int = 8,
    rule_id: int = 1001,
    full_log: str = "cmd.exe /c whoami",
    attacker_ip: str | None = None,
) -> WazuhLog:
    return WazuhLog(
        id=uuid4(),
        timestamp=datetime.now(UTC),
        source_agent="WS-01",
        source_ip="10.0.0.10",
        attacker_ip=attacker_ip,
        rule_id=rule_id,
        rule_level=rule_level,
        rule_description="Suspicious activity",
        full_log=full_log,
        mitre_technique="T1021",
        decoder_name="windows-eventlog",
    )


def _make_rag(tier: str, anomaly_score: float = 0.0, has_baseline: bool = True) -> RagContext:
    return RagContext(
        asset_name="asset-01",
        asset_criticality=tier,
        asset_description="Production system",
        similar_incidents=[],
        ueba=UEBAMetrics(
            has_baseline=has_baseline,
            baseline_description="Normal business-hours activity",
            associated_users=["operator"],
            normal_activity_window="08:00-18:00",
            recent_anomalies=[],
            anomaly_score=anomaly_score,
        ),
    )


async def _run_pipeline(
    log: WazuhLog,
    ollama_client: _FakeOllamaClient,
    chromadb_client: _FakeChromaDBClient,
    shuffle_client: _FakeShuffleClient,
    suspicion_threshold: float = 0.5,
    slm_timeout: float = 10.0,
    llm_timeout: float = 45.0,
    response_policies: dict[int, object] | None = None,
) -> AegisReport | None:
    """Chain triage_log + analyze_log — mirrors the old single-shot process_log
    end-to-end so existing scenario assertions stay meaningful across the split."""
    escalated = await triage_log(
        log=log,
        ollama_client=ollama_client,
        chromadb_client=chromadb_client,
        suspicion_threshold=suspicion_threshold,
        slm_timeout=slm_timeout,
    )
    if escalated is None:
        return None
    return await analyze_log(
        escalated=escalated,
        ollama_client=ollama_client,
        shuffle_client=shuffle_client,
        llm_timeout=llm_timeout,
        response_policies=response_policies,  # type: ignore[arg-type]
    )


@pytest.mark.asyncio
async def test_pipeline_low_slm_confidence_discards_and_skips_llm() -> None:
    ollama = _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.49,
                "behavior_category": "normal",
                "reasoning_short": "Weak suspicious signal",
                "raw_probabilities": {"suspect": 0.49, "benign": 0.51},
            },
            "mistral-aegis": {
                "attack_confirmed": True,
                "confidence": 0.9,
                "attack_type": "Lateral movement",
                "severity": "critical",
                "affected_asset": "asset-01",
                "asset_criticality": "tier0",
                "plain_language_summary": "Threat",
                "recommended_action": "Isolate",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.9, "false_positive": 0.1},
            },
        }
    )
    chroma = _FakeChromaDBClient(_make_rag("tier0"))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(
        log=_make_log(),
        ollama_client=ollama,
        chromadb_client=chroma,
        shuffle_client=shuffle,
        suspicion_threshold=0.5,
        slm_timeout=10.0,
        llm_timeout=45.0,
    )

    assert result is None
    assert ollama.calls == ["qwen25-aegis"]
    assert shuffle.reports_sent == 0


def _suspect_ollama() -> _FakeOllamaClient:
    """SLM flags a suspect alert; LLM confirms — used to probe the UEBA gate."""
    return _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.85,
                "behavior_category": "normal",
                "reasoning_short": "SQL injection probe against product search",
                "raw_probabilities": {"suspect": 0.85, "benign": 0.15},
            },
            "mistral-aegis": {
                "attack_confirmed": True,
                "confidence": 0.9,
                "attack_type": "SQL injection",
                "severity": "high",
                "affected_asset": "asset-01",
                "asset_criticality": "tier2",
                "plain_language_summary": "Repeated SQLi probes from one host.",
                "recommended_action": "Block the source IP at the firewall.",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.9, "false_positive": 0.1},
            },
        }
    )


def _weak_suspect_ollama() -> _FakeOllamaClient:
    """SLM is suspect but weakly so (confidence below the FP-gate ceiling)."""
    return _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.55,
                "behavior_category": "normal",
                "reasoning_short": "Mildly unusual request pattern",
                "raw_probabilities": {"suspect": 0.55, "benign": 0.45},
            },
        }
    )


@pytest.mark.asyncio
async def test_pipeline_no_baseline_suspect_escalates_to_llm() -> None:
    # Unprofiled asset (has_baseline=False): a low-severity but SLM-suspect alert
    # must NOT be discarded — anomaly_score=0.0 means "unknown", not "normal".
    ollama = _suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=False))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=7), ollama, chroma, shuffle)

    assert result is not None
    assert ollama.calls == ["qwen25-aegis", "mistral-aegis"]
    assert shuffle.reports_sent == 1


@pytest.mark.asyncio
async def test_pipeline_baseline_normal_discards_weak_suspect_before_llm() -> None:
    # A real baseline that says "normal" (low anomaly) gates out a low-severity
    # alert on a non-critical asset ONLY when the SLM was weakly suspicious
    # (confidence below the gate ceiling) — the LLM is never called.
    ollama = _weak_suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=True))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=7), ollama, chroma, shuffle)

    assert result is None
    assert ollama.calls == ["qwen25-aegis"]
    assert shuffle.reports_sent == 0


@pytest.mark.asyncio
async def test_pipeline_baseline_normal_but_confident_slm_escalates() -> None:
    # The hardening: a calm profiled baseline must NOT silence a CONFIDENT SLM
    # suspicion (>= ceiling). The agreeing rule + model signal wins the gate.
    ollama = _suspect_ollama()  # SLM confidence 0.85, above the 0.6 ceiling
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=True))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=7), ollama, chroma, shuffle)

    assert result is not None
    assert ollama.calls == ["qwen25-aegis", "mistral-aegis"]
    assert shuffle.reports_sent == 1


@pytest.mark.asyncio
async def test_triage_requests_identity_sync_for_unprofiled_asset() -> None:
    # Unprofiled asset (has_baseline=False) → triage asks for an identity sync.
    ollama = _suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=False))
    requested: list[str] = []

    async def _cb(asset_id: str) -> None:
        requested.append(asset_id)

    await triage_log(
        log=_make_log(rule_level=7),
        ollama_client=ollama,
        chromadb_client=chroma,
        on_unprofiled_asset=_cb,
    )
    assert requested == ["10.0.0.10"]  # _make_log source_ip


@pytest.mark.asyncio
async def test_triage_no_identity_sync_when_profiled() -> None:
    ollama = _suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=True))
    requested: list[str] = []

    async def _cb(asset_id: str) -> None:
        requested.append(asset_id)

    await triage_log(
        log=_make_log(rule_level=10),
        ollama_client=ollama,
        chromadb_client=chroma,
        on_unprofiled_asset=_cb,
    )
    assert requested == []


@pytest.mark.asyncio
async def test_pipeline_uses_llm_authored_action_verbatim() -> None:
    # The LLM owns recommended_action — no deterministic playbook override. The
    # decision action must be exactly what the LLM produced.
    ollama = _suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=False))
    shuffle = _FakeShuffleClient()
    log = _make_log(
        rule_level=10,
        rule_id=31103,
        full_log='172.18.0.1 - - [..] "GET /rest/products/search?q=x HTTP/1.1" 500',
        attacker_ip="172.18.0.1",
    )

    result = await _run_pipeline(log, ollama, chroma, shuffle)

    assert result is not None
    # _suspect_ollama's LLM action, passed through untouched.
    assert result.decision.recommended_action == "Block the source IP at the firewall."


@pytest.mark.asyncio
async def test_pipeline_tier0_high_confidence_results_critical() -> None:
    ollama = _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.92,
                "behavior_category": "lateral_movement",
                "reasoning_short": "High confidence suspicious behavior",
                "raw_probabilities": {"suspect": 0.92, "benign": 0.08},
            },
            "mistral-aegis": {
                "attack_confirmed": True,
                "confidence": 0.93,
                "attack_type": "Lateral movement",
                "severity": "critical",
                "affected_asset": "asset-01",
                "asset_criticality": "tier0",
                "plain_language_summary": "Threat confirmed",
                "recommended_action": "Isolate",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.93, "false_positive": 0.07},
            },
        }
    )
    chroma = _FakeChromaDBClient(_make_rag("tier0"))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=12), ollama, chroma, shuffle)

    assert result is not None
    assert result.risk_score.danger_score >= 0.8
    assert result.decision.severity == "critical"
    assert result.decision.auto_remediation_allowed is False
    assert result.decision.requires_human_validation is True


@pytest.mark.asyncio
async def test_pipeline_tier2_medium_confidence_in_expected_range() -> None:
    ollama = _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.6,
                "behavior_category": "privilege_escalation",
                "reasoning_short": "Moderate suspicious behavior",
                "raw_probabilities": {"suspect": 0.6, "benign": 0.4},
            },
            "mistral-aegis": {
                "attack_confirmed": True,
                "confidence": 0.62,
                "attack_type": "Privilege escalation",
                "severity": "high",
                "affected_asset": "asset-01",
                "asset_criticality": "tier2",
                "plain_language_summary": "Potential threat",
                "recommended_action": "Investigate",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.62, "false_positive": 0.38},
            },
        }
    )
    # anomaly_score=0.4: slightly elevated — passes UEBA gate (not a clear FP)
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.4))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=8), ollama, chroma, shuffle)

    assert result is not None
    assert 0.3 <= result.risk_score.danger_score < 0.8
    assert result.decision.auto_remediation_allowed is False
    assert result.decision.requires_human_validation is True


@pytest.mark.asyncio
async def test_pipeline_llm_timeout_uses_slm_fallback() -> None:
    ollama = _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.78,
                "behavior_category": "lateral_movement",
                "reasoning_short": "Suspicious behavior",
                "raw_probabilities": {"suspect": 0.78, "benign": 0.22},
            },
            "mistral-aegis": TimeoutError("llm timeout"),
        }
    )
    chroma = _FakeChromaDBClient(_make_rag("tier1"))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=10), ollama, chroma, shuffle)

    assert result is not None
    assert result.llm_analysis is None
    assert result.risk_score.score_breakdown["llm_contribution"] == pytest.approx(0.39, rel=1e-2)
    assert result.decision.auto_remediation_allowed is False
    assert result.decision.requires_human_validation is True


@pytest.mark.asyncio
async def test_pipeline_soar_error_does_not_crash() -> None:
    ollama = _FakeOllamaClient(
        responses={
            "qwen25-aegis": {
                "is_suspect": True,
                "confidence": 0.8,
                "behavior_category": "lateral_movement",
                "reasoning_short": "Suspicious behavior",
                "raw_probabilities": {"suspect": 0.8, "benign": 0.2},
            },
            "mistral-aegis": {
                "attack_confirmed": True,
                "confidence": 0.82,
                "attack_type": "Lateral movement",
                "severity": "high",
                "affected_asset": "asset-01",
                "asset_criticality": "tier1",
                "plain_language_summary": "Threat confirmed",
                "recommended_action": "Investigate",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.82, "false_positive": 0.18},
            },
        }
    )
    chroma = _FakeChromaDBClient(_make_rag("tier1"))
    shuffle = _FakeShuffleClient(should_fail=True)

    result = await _run_pipeline(_make_log(rule_level=10), ollama, chroma, shuffle)

    assert result is not None
    assert result.decision.auto_remediation_allowed is False
    assert result.decision.requires_human_validation is True


@pytest.mark.asyncio
async def test_pipeline_applies_preapproved_response_policy() -> None:
    # A human pre-approved policy for this Wazuh rule → response recorded on the report
    # (auto-applied), auto_remediation_allowed True, but the human still gets the incident.
    from aegis.soar.response_policy import ResponsePolicy

    ollama = _suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=False))
    shuffle = _FakeShuffleClient()
    log = _make_log(
        rule_level=10,
        rule_id=5712,
        full_log="203.0.113.7 sshd: failed password for root",
        attacker_ip="203.0.113.7",
    )
    policies = {5712: ResponsePolicy(5712, "Block {actor} at the firewall", auto=True)}

    result = await _run_pipeline(log, ollama, chroma, shuffle, response_policies=policies)

    assert result is not None
    applied = result.decision.applied_response
    assert applied is not None
    assert applied.rule_id == 5712
    assert applied.auto_applied is True
    assert "203.0.113.7" in applied.action
    assert result.decision.auto_remediation_allowed is True
    assert result.decision.requires_human_validation is True  # human still receives it


@pytest.mark.asyncio
async def test_pipeline_no_policy_means_no_applied_response() -> None:
    ollama = _suspect_ollama()
    chroma = _FakeChromaDBClient(_make_rag("tier2", anomaly_score=0.0, has_baseline=False))
    shuffle = _FakeShuffleClient()

    result = await _run_pipeline(_make_log(rule_level=7), ollama, chroma, shuffle)

    assert result is not None
    assert result.decision.applied_response is None
    assert result.decision.auto_remediation_allowed is False
