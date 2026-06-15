"""Shared helpers for the Level-1 (deterministic, no-Pi) KPI benchmarks.

The pipeline is driven with a fake Ollama that replays *canonical* responses
(what a correct model should say), so these KPIs measure the deterministic
behaviour around the model — parse correctness, the playbook action specificity,
severity calibration and gate outcomes — not the live model's accuracy (that is
the Level-2 live harness).
"""

from __future__ import annotations

import json
import pathlib
from typing import Any

from aegis.collectors.wazuh_forwarder import WazuhAlertParser
from aegis.middleware.models import AegisReport, RagContext, UEBAMetrics, WazuhLog
from aegis.middleware.pipeline import analyze_log, triage_log

CORPUS_DIR = pathlib.Path(__file__).resolve().parents[1] / "fixtures" / "corpus"

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

CorpusEntry = tuple[str, dict[str, Any], dict[str, Any]]


def load_corpus() -> list[CorpusEntry]:
    """Return [(corpus_id, raw_alert, label)] from the seed corpus."""
    alerts = json.loads((CORPUS_DIR / "alerts.json").read_text(encoding="utf-8"))
    labels = json.loads((CORPUS_DIR / "labels.json").read_text(encoding="utf-8"))
    assert set(alerts) == set(labels), "corpus alerts/labels id mismatch"
    return [(cid, alerts[cid], labels[cid]) for cid in alerts]


def severity_ge(actual: str, minimum: str) -> bool:
    """True when ``actual`` severity is at least ``minimum``."""
    return _SEVERITY_RANK[actual] >= _SEVERITY_RANK[minimum]


def unprofiled_context(asset: str) -> RagContext:
    """A tier2 asset with no UEBA baseline (the common pre-seeding case)."""
    return RagContext(
        asset_name=asset,
        asset_criticality="tier2",
        asset_description="Unknown asset",
        similar_incidents=[],
        ueba=UEBAMetrics(
            has_baseline=False,
            baseline_description="No baseline",
            associated_users=[],
            normal_activity_window="Unknown",
            recent_anomalies=[],
            anomaly_score=0.0,
        ),
    )


class FakeOllama:
    """Replays canonical SLM/LLM responses (model name 'slm' vs 'llm')."""

    def __init__(self, *, is_attack: bool) -> None:
        self.is_attack = is_attack
        self.calls: list[str] = []

    async def __aenter__(self) -> FakeOllama:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def generate(
        self,
        model: str,
        prompt: str,
        timeout: float,
        keep_alive: int = 300,
        num_predict: int | None = None,
        format_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        _ = (prompt, timeout, keep_alive, num_predict, format_schema)
        self.calls.append(model)
        if model == "slm":
            return {
                "is_suspect": True,
                "confidence": 0.85,
                "behavior_category": "normal",
                "reasoning_short": "canonical triage",
                "raw_probabilities": {"suspect": 0.85, "benign": 0.15},
            }
        return {
            "attack_confirmed": self.is_attack,
            "confidence": 0.9,
            "attack_type": "canonical attack type",
            "severity": "high",
            "affected_asset": "asset",
            "asset_criticality": "tier2",
            "plain_language_summary": "Canonical summary of the observed activity.",
            "recommended_action": "Investigate further.",
            "requires_human_validation": True,
            "raw_probabilities": {"attack": 0.9, "false_positive": 0.1},
        }


class _FakeChroma:
    async def __aenter__(self) -> _FakeChroma:
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        return None

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        return unprofiled_context(asset_identifier)


class _FakeShuffle:
    def __init__(self) -> None:
        self.sent = 0

    async def send_report(self, report: Any) -> bool:
        _ = report
        self.sent += 1
        return True


# Production noise filter: infra-host self-monitoring rules dropped before triage
# (see WAZUH_EXCLUDED_RULES). Used by the false-positive KPI.
NOISE_FILTER: frozenset[int] = frozenset({533})


async def run_canonical(
    raw_alert: dict[str, Any],
    *,
    is_attack: bool,
    excluded_rules: frozenset[int] = frozenset(),
) -> tuple[WazuhLog | None, AegisReport | None]:
    """Parse → triage → analyze one raw alert with canonical model responses."""
    parsed = WazuhAlertParser.parse_alert(raw_alert, min_level=7, excluded_rules=excluded_rules)
    if parsed is None:
        return None, None

    ollama = FakeOllama(is_attack=is_attack)
    escalated = await triage_log(
        log=parsed,
        ollama_client=ollama,  # type: ignore[arg-type]
        chromadb_client=_FakeChroma(),  # type: ignore[arg-type]
        slm_model="slm",
    )
    if escalated is None:
        return parsed, None

    report = await analyze_log(
        escalated=escalated,
        ollama_client=ollama,  # type: ignore[arg-type]
        shuffle_client=_FakeShuffle(),  # type: ignore[arg-type]
        llm_model="llm",
        use_schema=False,
    )
    return parsed, report
