"""Level-1 KPIs for the UEBA<->ChromaDB identity connector."""

from __future__ import annotations

from typing import Any

import pytest

import aegis.rag.client as rag_client_module
from aegis.middleware.models import RagContext, UEBAMetrics
from aegis.rag.client import ChromaDBClient

pytestmark = pytest.mark.benchmark


class _FakeCollection:
    def __init__(self) -> None:
        self.upserts = 0

    async def upsert(self, ids: Any, metadatas: Any, embeddings: Any) -> None:
        _ = (ids, metadatas, embeddings)
        self.upserts += 1

    async def get(self, ids: Any) -> dict[str, Any]:
        _ = ids
        return {"metadatas": [{}]}


class _FakeClient:
    def __init__(self, collection: _FakeCollection) -> None:
        self._collection = collection

    async def get_or_create_collection(self, name: str) -> _FakeCollection:
        _ = name
        return self._collection

    async def close(self) -> None:
        return None


class _FakeModule:
    def __init__(self, client: _FakeClient) -> None:
        self._client = client

    def AsyncHttpClient(self, host: str, port: int) -> _FakeClient:  # noqa: N802
        _ = (host, port)
        return self._client


class _OkConnector:
    def __init__(self, context: RagContext) -> None:
        self._context = context

    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        _ = asset_identifier
        return self._context


class _FailingConnector:
    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        _ = asset_identifier
        raise ConnectionError("ldap unreachable")


def _ctx() -> RagContext:
    return RagContext(
        asset_name="dc-01",
        asset_criticality="tier0",
        asset_description="Domain Controller",
        similar_incidents=[],
        ueba=UEBAMetrics(
            has_baseline=True,
            baseline_description="AD baseline",
            associated_users=["admin"],
            normal_activity_window="08:00-18:00",
            recent_anomalies=[],
            anomaly_score=0.4,
        ),
    )


@pytest.mark.asyncio
async def test_connector_kpis(monkeypatch: pytest.MonkeyPatch, kpi_sink: dict[str, Any]) -> None:
    collection = _FakeCollection()
    client = _FakeClient(collection)
    monkeypatch.setattr(rag_client_module, "_get_chromadb_module", lambda: _FakeModule(client))

    async with ChromaDBClient(host="x", port=8000) as chroma:
        ok1 = await chroma.sync_asset_identity("10.0.0.10", _OkConnector(_ctx()))  # type: ignore[arg-type]
        ok2 = await chroma.sync_asset_identity("10.0.0.10", _OkConnector(_ctx()))  # type: ignore[arg-type]
        fallback = await chroma.sync_asset_identity("10.0.0.99", _FailingConnector())  # type: ignore[arg-type]

    kpi = {
        "sync_success": int(ok1) + int(ok2),
        "idempotent": bool(ok1 and ok2),
        "fallback_graceful": bool(fallback),  # LDAP failure → default tier2, no crash
        "upserts": collection.upserts,
    }
    kpi_sink["connector"] = kpi

    assert ok1
    assert ok2
    assert fallback
    assert collection.upserts == 3
