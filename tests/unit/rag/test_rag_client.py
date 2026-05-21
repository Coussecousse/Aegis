"""Unit tests for ChromaDBClient metadata lookup and fallbacks."""

from __future__ import annotations

from typing import Any
from uuid import uuid4

import httpx
import pytest

from aegis.middleware.models import LlmResponse, SlmResponse
from aegis.middleware.risk_scorer import compute_risk_score
from aegis.rag import client as rag_client_module
from aegis.rag.client import ChromaDBClient


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, Any]) -> None:
        self.status_code = status_code
        self._payload = payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            request = httpx.Request("POST", "http://chromadb/api")
            response = httpx.Response(self.status_code, request=request)
            raise httpx.HTTPStatusError("request failed", request=request, response=response)

    def json(self) -> dict[str, Any]:
        return self._payload


class _FakeAsyncClient:
    planned: list[Any] = []

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _ = args
        _ = kwargs

    async def post(self, url: str, json: dict[str, Any]) -> _FakeResponse:
        _ = url
        _ = json
        current = _FakeAsyncClient.planned.pop(0)
        if isinstance(current, Exception):
            raise current
        return current

    async def aclose(self) -> None:
        return None


@pytest.mark.asyncio
async def test_get_asset_context_found_returns_tier() -> None:
    _FakeAsyncClient.planned = [
        _FakeResponse(200, {"id": "col-1"}),
        _FakeResponse(
            200,
            {
                "metadatas": [
                    [
                        {
                            "asset_id": "10.0.0.10",
                            "asset_name": "DC-01",
                            "criticality_tier": "tier0",
                            "asset_description": "Domain controller",
                            "similar_incidents": [str(uuid4())],
                            "ueba": {
                                "baseline_description": "Business hours authentication pattern",
                                "associated_users": ["domain_admin"],
                                "normal_activity_window": "08:00-18:00",
                                "recent_anomalies": [],
                                "anomaly_score": 0.2,
                            },
                        }
                    ]
                ]
            },
        ),
    ]

    original = rag_client_module.httpx.AsyncClient
    rag_client_module.httpx.AsyncClient = _FakeAsyncClient  # type: ignore[assignment]
    try:
        async with ChromaDBClient(host="chromadb", port=8000) as client:
            context = await client.get_asset_context("10.0.0.10")
    finally:
        rag_client_module.httpx.AsyncClient = original  # type: ignore[assignment]

    assert context.asset_name == "DC-01"
    assert context.asset_criticality == "tier0"


@pytest.mark.asyncio
async def test_get_asset_context_not_found_fallback_tier2(caplog: pytest.LogCaptureFixture) -> None:
    _FakeAsyncClient.planned = [
        _FakeResponse(200, {"id": "col-1"}),
        _FakeResponse(200, {"metadatas": []}),
    ]

    original = rag_client_module.httpx.AsyncClient
    rag_client_module.httpx.AsyncClient = _FakeAsyncClient  # type: ignore[assignment]
    try:
        async with ChromaDBClient(host="chromadb", port=8000) as client:
            context = await client.get_asset_context("10.0.0.99")
    finally:
        rag_client_module.httpx.AsyncClient = original  # type: ignore[assignment]

    assert context.asset_criticality == "tier2"
    assert "asset_id=10.0.0.99 not found in ChromaDB, defaulting to tier2" in caplog.text


@pytest.mark.asyncio
async def test_tier0_context_applies_criticality_multiplier() -> None:
    _FakeAsyncClient.planned = [
        _FakeResponse(200, {"id": "col-1"}),
        _FakeResponse(
            200,
            {
                "metadatas": [
                    [
                        {
                            "asset_id": "dc-01",
                            "asset_name": "dc-01",
                            "criticality_tier": "tier0",
                            "asset_description": "Domain controller",
                            "ueba": {
                                "baseline_description": "Normal",
                                "associated_users": [],
                                "normal_activity_window": "08:00-18:00",
                                "recent_anomalies": [],
                                "anomaly_score": 0.0,
                            },
                        }
                    ]
                ]
            },
        ),
    ]

    original = rag_client_module.httpx.AsyncClient
    rag_client_module.httpx.AsyncClient = _FakeAsyncClient  # type: ignore[assignment]
    try:
        async with ChromaDBClient(host="chromadb", port=8000) as client:
            context = await client.get_asset_context("dc-01")
    finally:
        rag_client_module.httpx.AsyncClient = original  # type: ignore[assignment]

    slm = SlmResponse(
        is_suspect=True,
        confidence=0.9,
        behavior_category="lateral_movement",
        reasoning_short="Suspicious",
        raw_probabilities={"suspect": 0.9, "benign": 0.1},
    )
    llm = LlmResponse(
        attack_confirmed=True,
        confidence=0.9,
        attack_type="Lateral movement",
        severity="critical",
        affected_asset="dc-01",
        asset_criticality="tier0",
        plain_language_summary="Threat confirmed",
        recommended_action="Isolate",
        requires_human_validation=True,
        raw_probabilities={"attack": 0.9, "false_positive": 0.1},
    )
    score = compute_risk_score(
        slm=slm,
        llm=llm,
        rule_level=10,
        asset_criticality=context.asset_criticality,
    )

    assert score.score_breakdown["criticality_multiplier"] == 1.5


@pytest.mark.asyncio
async def test_get_asset_context_timeout_fallback_tier2() -> None:
    _FakeAsyncClient.planned = [
        _FakeResponse(200, {"id": "col-1"}),
        httpx.TimeoutException("timeout"),
    ]

    original = rag_client_module.httpx.AsyncClient
    rag_client_module.httpx.AsyncClient = _FakeAsyncClient  # type: ignore[assignment]
    try:
        async with ChromaDBClient(host="chromadb", port=8000) as client:
            context = await client.get_asset_context("10.0.0.20")
    finally:
        rag_client_module.httpx.AsyncClient = original  # type: ignore[assignment]

    assert context.asset_criticality == "tier2"


@pytest.mark.asyncio
async def test_get_asset_context_missing_ueba_uses_neutral_defaults() -> None:
    _FakeAsyncClient.planned = [
        _FakeResponse(200, {"id": "col-1"}),
        _FakeResponse(
            200,
            {
                "metadatas": [
                    [
                        {
                            "asset_id": "app-01",
                            "asset_name": "app-01",
                            "criticality_tier": "tier1",
                            "asset_description": "Application server",
                        }
                    ]
                ]
            },
        ),
    ]

    original = rag_client_module.httpx.AsyncClient
    rag_client_module.httpx.AsyncClient = _FakeAsyncClient  # type: ignore[assignment]
    try:
        async with ChromaDBClient(host="chromadb", port=8000) as client:
            context = await client.get_asset_context("app-01")
    finally:
        rag_client_module.httpx.AsyncClient = original  # type: ignore[assignment]

    assert context.ueba.anomaly_score == 0.0
    assert context.ueba.associated_users == []
    assert context.ueba.recent_anomalies == []
