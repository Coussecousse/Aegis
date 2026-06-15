"""Integration test for end-to-end identity sync and alert analysis."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from aegis.middleware.consumer_identity import IdentityProcessor
from aegis.middleware.models import RagContext, UEBAMetrics, WazuhLog
from aegis.middleware.pipeline import analyze_log, triage_log
from aegis.rag.ldap import LdapConfig


class _FakeIdentityConnector:
    def __init__(self, context: RagContext) -> None:
        self._context = context

    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        _ = asset_identifier
        return self._context


class _MemoryChromaDBClient:
    def __init__(self) -> None:
        self._contexts: dict[str, RagContext] = {}

    async def sync_asset_identity(self, asset_id: str, connector: _FakeIdentityConnector) -> bool:
        context = await connector.fetch_identity_context(asset_id)
        self._contexts[asset_id] = context
        return True

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        return self._contexts[asset_identifier]

    async def record_activity(self, asset_identifier: str, now: float | None = None) -> RagContext:
        _ = now
        return self._contexts[asset_identifier]


class _FakeOllamaClient:
    def __init__(self) -> None:
        self.responses: dict[str, dict[str, Any]] = {
            "tinyllama-aegis": {
                "is_suspect": True,
                "confidence": 0.92,
                "behavior_category": "lateral_movement",
                "reasoning_short": "High confidence suspicious behavior",
                "raw_probabilities": {"suspect": 0.92, "benign": 0.08},
            },
            "mistral-aegis": {
                "attack_confirmed": True,
                "confidence": 0.9,
                "attack_type": "Lateral movement",
                "severity": "critical",
                "affected_asset": "dc-01",
                "asset_criticality": "tier0",
                "plain_language_summary": "Threat confirmed",
                "recommended_action": "Isolate",
                "requires_human_validation": True,
                "raw_probabilities": {"attack": 0.9, "false_positive": 0.1},
            },
        }

    async def generate(
        self,
        model: str,
        prompt: str,
        timeout: float,
        keep_alive: int = 300,
        num_predict: int | None = None,
    ) -> dict[str, Any]:
        _ = prompt
        _ = timeout
        _ = keep_alive
        _ = num_predict
        return self.responses[model]


class _FakeShuffleClient:
    def __init__(self) -> None:
        self.reports_sent: int = 0

    async def send_report(self, report: Any) -> bool:
        _ = report
        self.reports_sent += 1
        return True


def _make_log() -> WazuhLog:
    return WazuhLog(
        id=uuid4(),
        timestamp=datetime.now(UTC),
        source_agent="DC-01",
        source_ip="10.0.0.10",
        rule_id=1001,
        rule_level=12,
        rule_description="Suspicious domain controller activity",
        full_log="event=failed_logon user=admin-user",
        mitre_technique="T1021",
        decoder_name="windows-eventlog",
    )


@pytest.mark.asyncio
async def test_identity_sync_pipeline_applies_tier0_multiplier_and_human_gate() -> None:
    tier0_context = RagContext(
        asset_name="dc-01",
        asset_criticality="tier0",
        asset_description="Domain Controller",
        similar_incidents=[],
        ueba=UEBAMetrics(
            baseline_description="Identity baseline from AD",
            associated_users=["admin-user"],
            normal_activity_window="Unknown",
            recent_anomalies=["CN=Domain Admins,CN=Users,DC=aerotech,DC=local"],
            anomaly_score=1.0,
        ),
    )

    connector = _FakeIdentityConnector(tier0_context)
    chroma = _MemoryChromaDBClient()

    # Drive the identity processor directly (clients injected, bypassing __aenter__).
    identity_processor = IdentityProcessor(
        ldap_config=LdapConfig(host="x", base_dn="dc=x", bind_dn="", bind_password="")
    )
    identity_processor._chroma = chroma  # type: ignore[assignment]  # noqa: SLF001
    identity_processor._connector = connector  # type: ignore[assignment]  # noqa: SLF001

    async def _publish(routing_key: str, body: bytes) -> None:  # pragma: no cover
        raise AssertionError("identity stage must not publish")

    await identity_processor.process({"asset_id": "10.0.0.10"}, _publish)
    assert "10.0.0.10" in chroma._contexts  # noqa: SLF001

    ollama = _FakeOllamaClient()
    shuffle = _FakeShuffleClient()

    escalated = await triage_log(
        log=_make_log(),
        ollama_client=ollama,
        chromadb_client=chroma,
    )
    assert escalated is not None

    report = await analyze_log(
        escalated=escalated,
        ollama_client=ollama,
        shuffle_client=shuffle,
    )

    assert report is not None
    assert report.risk_score.score_breakdown["criticality_multiplier"] == 1.5
    assert report.decision.requires_human_validation is True
    assert report.decision.auto_remediation_allowed is False
