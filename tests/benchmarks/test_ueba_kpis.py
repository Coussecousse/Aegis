"""Level-1 UEBA-gate KPIs: the triage gate decision matrix."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import pytest

from aegis.middleware.models import RagContext, UEBAMetrics, WazuhLog
from aegis.middleware.pipeline import triage_log

pytestmark = pytest.mark.benchmark


class _FakeOllama:
    def __init__(self, *, is_suspect: bool, confidence: float) -> None:
        self.is_suspect = is_suspect
        self.confidence = confidence

    async def generate(self, model: str, prompt: str, timeout: float, **_: Any) -> dict[str, Any]:
        _ = (model, prompt, timeout)
        return {
            "is_suspect": self.is_suspect,
            "confidence": self.confidence,
            "behavior_category": "normal",
            "reasoning_short": "x",
            "raw_probabilities": {"suspect": self.confidence, "benign": 1 - self.confidence},
        }


class _FakeChroma:
    def __init__(self, context: RagContext) -> None:
        self.context = context

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        _ = asset_identifier
        return self.context


def _ctx(*, tier: str, has_baseline: bool, anomaly: float) -> RagContext:
    return RagContext(
        asset_name="a",
        asset_criticality=tier,  # type: ignore[arg-type]
        asset_description="d",
        similar_incidents=[],
        ueba=UEBAMetrics(
            has_baseline=has_baseline,
            baseline_description="b",
            associated_users=[],
            normal_activity_window="w",
            recent_anomalies=[],
            anomaly_score=anomaly,
        ),
    )


def _log(level: int) -> WazuhLog:
    return WazuhLog(
        id=uuid4(),
        timestamp=datetime.now(UTC),
        source_agent="a",
        source_ip="10.0.0.1",
        rule_id=1234,
        rule_level=level,
        rule_description="d",
        full_log="log",
        mitre_technique=None,
        decoder_name=None,
    )


_UNPROFILED = _ctx(tier="tier2", has_baseline=False, anomaly=0.0)
_NORMAL_T2 = _ctx(tier="tier2", has_baseline=True, anomaly=0.0)
_ANOMALOUS_T2 = _ctx(tier="tier2", has_baseline=True, anomaly=0.5)
_NORMAL_T0 = _ctx(tier="tier0", has_baseline=True, anomaly=0.0)

# (case, level, suspect, confidence, ctx, expected_outcome)
_CASES = [
    ("unprofiled_lowsev_suspect", 7, True, 0.85, _UNPROFILED, "escalate"),
    ("profiled_normal_lowsev", 7, True, 0.85, _NORMAL_T2, "discard"),
    ("profiled_normal_highsev", 10, True, 0.85, _NORMAL_T2, "escalate"),
    ("profiled_anomalous_lowsev", 7, True, 0.85, _ANOMALOUS_T2, "escalate"),
    ("tier0_normal_lowsev", 7, True, 0.85, _NORMAL_T0, "escalate"),
    ("not_suspect", 10, False, 0.2, _UNPROFILED, "discard"),
]


@pytest.mark.asyncio
async def test_ueba_gate_matrix(kpi_sink: dict[str, Any]) -> None:
    kpi = {"total": 0, "correct": 0, "escalate": 0, "discard": 0, "failures": []}

    for name, level, suspect, conf, ctx, expected in _CASES:
        kpi["total"] += 1
        escalated = await triage_log(
            log=_log(level),
            ollama_client=_FakeOllama(is_suspect=suspect, confidence=conf),  # type: ignore[arg-type]
            chromadb_client=_FakeChroma(ctx),  # type: ignore[arg-type]
            slm_model="slm",
        )
        outcome = "escalate" if escalated is not None else "discard"
        kpi[outcome] += 1
        if outcome == expected:
            kpi["correct"] += 1
        else:
            kpi["failures"].append(f"{name}: got {outcome}, expected {expected}")

    kpi_sink["ueba_gate"] = kpi
    assert kpi["correct"] == kpi["total"], kpi["failures"]
