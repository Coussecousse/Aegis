"""Unit tests for ChromaDBClient lookups and fallbacks."""

from __future__ import annotations

from typing import Any
from unittest.mock import AsyncMock

import httpx
import pytest

from aegis.middleware.models import LlmResponse, RagContext, SlmResponse, UEBAMetrics
from aegis.middleware.risk_scorer import compute_risk_score
from aegis.rag import client as rag_client_module
from aegis.rag.base import BaseIdentityConnector
from aegis.rag.client import ChromaDBClient


class _FakeChromaModule:
    def __init__(self, collection: _FakeCollection) -> None:
        self._collection = collection
        self.AsyncHttpClient = self._build_async_http_client()

    def _build_async_http_client(self) -> Any:
        async def _async_http_client(host: str, port: int) -> _FakeChromaClient:
            _ = host
            _ = port
            return _FakeChromaClient(self._collection)

        return _async_http_client


class _FakeChromaModuleSyncOnly:
    def __init__(self, collection: _FakeCollectionSync) -> None:
        self._collection = collection
        self.HttpClient = self._build_http_client()

    def _build_http_client(self) -> Any:
        def _http_client(host: str, port: int) -> _FakeChromaClientSync:
            _ = host
            _ = port
            return _FakeChromaClientSync(self._collection)

        return _http_client


class _FakeCollection:
    def __init__(self, get_result: Any = None, get_error: Exception | None = None) -> None:
        self._get_result = get_result
        self._get_error = get_error
        self.upsert_calls = 0
        self.last_upsert_kwargs: dict[str, Any] = {}

    async def get(self, ids: list[str]) -> dict[str, Any]:
        _ = ids
        if self._get_error is not None:
            raise self._get_error
        return self._get_result if isinstance(self._get_result, dict) else {"metadatas": []}

    async def upsert(self, **kwargs: Any) -> None:
        self.last_upsert_kwargs = kwargs
        self.upsert_calls += 1


class _FakeCollectionSync:
    def __init__(self, get_result: Any = None, get_error: Exception | None = None) -> None:
        self._get_result = get_result
        self._get_error = get_error
        self.upsert_calls = 0
        self.last_upsert_kwargs: dict[str, Any] = {}

    def get(self, ids: list[str]) -> dict[str, Any]:
        _ = ids
        if self._get_error is not None:
            raise self._get_error
        return self._get_result if isinstance(self._get_result, dict) else {"metadatas": []}

    def upsert(self, **kwargs: Any) -> None:
        self.last_upsert_kwargs = kwargs
        self.upsert_calls += 1


class _FakeIdentityConnector(BaseIdentityConnector):
    def __init__(self, context: RagContext) -> None:
        self.fetch_identity_context_mock: AsyncMock = AsyncMock(return_value=context)

    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        return await self.fetch_identity_context_mock(asset_identifier)


class _FakeChromaClient:
    def __init__(self, collection: _FakeCollection) -> None:
        self._collection = collection

    async def get_or_create_collection(self, name: str) -> _FakeCollection:
        _ = name
        return self._collection


class _FakeChromaClientSync:
    def __init__(self, collection: _FakeCollectionSync) -> None:
        self._collection = collection

    def get_or_create_collection(self, name: str) -> _FakeCollectionSync:
        _ = name
        return self._collection


@pytest.mark.asyncio
async def test_get_asset_context_found_tier0(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = _FakeCollection(
        get_result={
            "metadatas": [
                {
                    "asset_name": "DC-01",
                    "asset_criticality": "tier0",
                    "asset_description": "Domain controller",
                    "similar_incidents": '["inc-1"]',
                    "baseline_description": "Business hours",
                    "associated_users": '["domain_admin"]',
                    "normal_activity_window": "08:00-18:00",
                    "recent_anomalies": '["night login"]',
                    "anomaly_score": "0.2",
                }
            ]
        }
    )

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModule(collection),
    )

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        context = await client.get_asset_context("dc-01")

    assert context.asset_criticality == "tier0"
    assert context.ueba.has_baseline is True


@pytest.mark.asyncio
async def test_get_asset_context_uses_sync_fallback_when_async_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = _FakeCollectionSync(
        get_result={
            "metadatas": [
                {
                    "asset_name": "APP-01",
                    "asset_criticality": "tier1",
                    "asset_description": "Application server",
                    "similar_incidents": "[]",
                }
            ]
        }
    )

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModuleSyncOnly(collection),
    )

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        context = await client.get_asset_context("app-01")

    assert context.asset_criticality == "tier1"


@pytest.mark.asyncio
async def test_get_asset_context_not_found_fallback_tier2(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    collection = _FakeCollection(get_result={"metadatas": []})

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModule(collection),
    )

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        context = await client.get_asset_context("missing-asset")

    assert context.asset_criticality == "tier2"
    assert context.ueba.has_baseline is False
    assert "not found in ChromaDB" in caplog.text


@pytest.mark.asyncio
async def test_get_asset_context_timeout_returns_tier2(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = _FakeCollection(get_error=httpx.TimeoutException("timeout"))

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModule(collection),
    )

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        context = await client.get_asset_context("dc-01")

    assert context.asset_criticality == "tier2"


@pytest.mark.asyncio
async def test_index_asset_calls_upsert_once(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = _FakeCollection(get_result={"metadatas": []})

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModule(collection),
    )

    context = RagContext(
        asset_name="dc-01",
        asset_criticality="tier0",
        asset_description="Domain controller",
        similar_incidents=["inc-1"],
        ueba=UEBAMetrics(
            baseline_description="Business hours",
            associated_users=["domain_admin"],
            normal_activity_window="08:00-18:00",
            recent_anomalies=[],
            anomaly_score=0.1,
        ),
    )

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        result = await client.index_asset(context)

    assert result is True
    assert collection.upsert_calls == 1


@pytest.mark.asyncio
async def test_sync_asset_identity_calls_connector_then_upsert(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    collection = _FakeCollection(get_result={"metadatas": []})

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModule(collection),
    )

    context = RagContext(
        asset_name="dc-01",
        asset_criticality="tier0",
        asset_description="Domain controller identity context",
        similar_incidents=[],
        ueba=UEBAMetrics(
            baseline_description="Identity baseline",
            associated_users=["admin-user"],
            normal_activity_window="Unknown",
            recent_anomalies=["CN=Domain Admins,CN=Users,DC=aerotech,DC=local"],
            anomaly_score=1.0,
        ),
    )
    connector = _FakeIdentityConnector(context)

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        result = await client.sync_asset_identity("dc-01", connector)

    assert result is True
    connector.fetch_identity_context_mock.assert_awaited_once_with("dc-01")
    assert collection.upsert_calls == 1
    assert collection.last_upsert_kwargs["ids"] == ["dc-01"]
    metadata = collection.last_upsert_kwargs["metadatas"][0]
    assert metadata["asset_criticality"] == "tier0"


@pytest.mark.asyncio
async def test_sync_asset_identity_connection_error_applies_tier2_fallback(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    collection = _FakeCollection(get_result={"metadatas": []})

    monkeypatch.setattr(
        rag_client_module,
        "_get_chromadb_module",
        lambda: _FakeChromaModule(collection),
    )

    connector = AsyncMock(spec=BaseIdentityConnector)
    connector.fetch_identity_context.side_effect = ConnectionError("ldap timeout")

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        result = await client.sync_asset_identity("missing-asset", connector)

    assert result is True
    assert collection.upsert_calls == 1
    metadata = collection.last_upsert_kwargs["metadatas"][0]
    assert metadata["asset_criticality"] == "tier2"
    assert "Failed to sync asset missing-asset, fallback data applied" in caplog.text


def test_tier0_mapping_yields_criticality_multiplier_1_5() -> None:
    slm = SlmResponse(
        is_suspect=True,
        confidence=0.9,
        behavior_category="lateral_movement",
        reasoning_short="Suspicious",
        raw_probabilities={"suspect": 0.9, "benign": 0.1},
    )
    llm = LlmResponse(
        attack_confirmed=True,
        confidence=0.91,
        attack_type="Lateral movement",
        severity="critical",
        affected_asset="dc-01",
        asset_criticality="tier0",
        plain_language_summary="Threat confirmed",
        recommended_action="Isolate",
        requires_human_validation=True,
        raw_probabilities={"attack": 0.91, "false_positive": 0.09},
    )

    score = compute_risk_score(slm=slm, llm=llm, rule_level=10, asset_criticality="tier0")

    assert score.score_breakdown["criticality_multiplier"] == 1.5


class _StatefulCollection:
    """Fake collection that persists upserts, so record_activity can be exercised
    across calls (a burst must actually raise the stored anomaly score)."""

    def __init__(self, metadata: dict[str, Any] | None) -> None:
        self._metadata = metadata
        self.upsert_calls = 0

    async def get(self, ids: list[str]) -> dict[str, Any]:
        _ = ids
        return {"metadatas": [self._metadata] if self._metadata is not None else []}

    async def upsert(self, **kwargs: Any) -> None:
        self._metadata = kwargs["metadatas"][0]
        self.upsert_calls += 1


@pytest.mark.asyncio
async def test_record_activity_raises_anomaly_on_burst(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = _StatefulCollection(
        {
            "asset_name": "WS-01",
            "asset_criticality": "tier2",
            "asset_description": "Workstation",
            "baseline_description": "behavioral",
            "associated_users": "[]",
            "normal_activity_window": "Unknown",
            "recent_anomalies": "[]",
            "anomaly_score": "0.0",
            "baseline_rate": "1.0",
            "event_timestamps": "[]",
        }
    )
    monkeypatch.setattr(
        rag_client_module, "_get_chromadb_module", lambda: _FakeChromaModule(collection)
    )

    scores: list[float] = []
    async with ChromaDBClient(host="chromadb", port=8000) as client:
        # A burst of events at the same instant (all inside the window).
        for _ in range(8):
            ctx = await client.record_activity("WS-01", now=1000.0)
            scores.append(ctx.ueba.anomaly_score)

    assert scores[0] == 0.0  # first event is at baseline
    assert max(scores) > 0.5  # the burst is detected at its peak
    # The EWMA baseline then absorbs sustained load, so the score decays back.
    assert scores[-1] < max(scores)
    assert all(0.0 <= s <= 1.0 for s in scores)
    assert collection.upsert_calls == 8


@pytest.mark.asyncio
async def test_record_activity_unprofiled_returns_default(monkeypatch: pytest.MonkeyPatch) -> None:
    collection = _StatefulCollection(None)  # asset absent from ChromaDB
    monkeypatch.setattr(
        rag_client_module, "_get_chromadb_module", lambda: _FakeChromaModule(collection)
    )

    async with ChromaDBClient(host="chromadb", port=8000) as client:
        ctx = await client.record_activity("unknown-asset", now=1000.0)

    assert ctx.asset_criticality == "tier2"
    assert ctx.ueba.has_baseline is False
    assert ctx.ueba.anomaly_score == 0.0
    assert collection.upsert_calls == 0  # nothing to record for an unprofiled asset
