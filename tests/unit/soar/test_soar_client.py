"""Unit tests for ShuffleClient delivery behavior."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

import httpx
import pytest

from aegis.middleware.models import (
    AegisReport,
    Decision,
    RagContext,
    RiskScore,
    SlmResponse,
    UEBAMetrics,
    WazuhLog,
)
from aegis.soar.client import ShuffleClient, SoarDeliveryError


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://shuffle/hook")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)


def _build_report(severity: str = "high") -> AegisReport:
    return AegisReport(
        alert_id=uuid4(),
        timestamp=datetime.now(UTC),
        source_log=WazuhLog(
            id=uuid4(),
            timestamp=datetime.now(UTC),
            source_agent="WS-01",
            source_ip="10.0.0.10",
            rule_id=1001,
            rule_level=9,
            rule_description="Suspicious command execution",
            full_log="cmd.exe /c net user",
            mitre_technique="T1021",
            decoder_name="windows-eventlog",
        ),
        slm_analysis=SlmResponse(
            is_suspect=True,
            confidence=0.78,
            behavior_category="lateral_movement",
            reasoning_short="Abnormal remote access pattern",
            raw_probabilities={"suspect": 0.78, "benign": 0.22},
        ),
        llm_analysis=None,
        rag_context=RagContext(
            asset_name="DC-01",
            asset_criticality="tier0",
            asset_description="Primary domain controller",
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description="Normal daytime authentication load",
                associated_users=["domain_admin"],
                normal_activity_window="08:00-18:00",
                recent_anomalies=[],
                anomaly_score=0.0,
            ),
        ),
        risk_score=RiskScore(
            danger_score=0.85,
            confidence_interval=0.02,
            uncertainty="low",
            score_breakdown={
                "slm_contribution": 0.23,
                "llm_contribution": 0.39,
                "rule_contribution": 0.12,
                "criticality_multiplier": 1.5,
            },
        ),
        decision=Decision(
            severity=severity,
            requires_human_validation=True,
            auto_remediation_allowed=False,
            recommended_action="Isolate source host",
        ),
        processing_time_ms=1200,
    )


@pytest.mark.asyncio
async def test_send_report_nominal_200() -> None:
    client = ShuffleClient("http://shuffle/hook")

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        _ = kwargs
        return _FakeResponse(200)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    sent = await client.send_report(_build_report())

    assert sent is True


@pytest.mark.asyncio
async def test_send_report_http_500_retries_then_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = ShuffleClient("http://shuffle/hook")
    attempts = 0
    sleeps: list[float] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        nonlocal attempts
        _ = args
        _ = kwargs
        attempts += 1
        return _FakeResponse(500)

    async def _sleep(duration: float) -> None:
        sleeps.append(duration)

    monkeypatch.setattr(asyncio, "sleep", _sleep)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    with pytest.raises(SoarDeliveryError):
        await client.send_report(_build_report())

    assert attempts == 3
    assert sleeps == [1.0, 2.0]


@pytest.mark.asyncio
async def test_send_report_uuid_serialization() -> None:
    client = ShuffleClient("http://shuffle/hook")
    payloads: list[dict[str, Any]] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        payloads.append(dict(kwargs["json"]))
        return _FakeResponse(200)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    report = _build_report()
    await client.send_report(report)

    assert isinstance(payloads[0]["alert_id"], str)
    assert isinstance(payloads[0]["source_log"]["id"], str)


@pytest.mark.asyncio
async def test_send_report_critical_decision_payload() -> None:
    client = ShuffleClient("http://shuffle/hook")
    payloads: list[dict[str, Any]] = []

    async def _post(*args: Any, **kwargs: Any) -> _FakeResponse:
        _ = args
        payloads.append(dict(kwargs["json"]))
        return _FakeResponse(200)

    client._client = httpx.AsyncClient()
    client._client.post = _post  # type: ignore[method-assign]

    report = _build_report(severity="critical")
    await client.send_report(report)

    assert payloads[0]["decision"]["severity"] == "critical"
