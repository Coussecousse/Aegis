"""Unit tests for PostgreSQL identity store client."""

from __future__ import annotations

import pytest

from aegis.identity_store.postgres_client import PostgresIdentityStore
from aegis.middleware.models import RagContext


def test_postgres_identity_store_init_stores_parameters() -> None:
    store = PostgresIdentityStore(
        host="postgres.local",
        port=5433,
        database="test_db",
        user="test_user",
        password="test_pass",  # pragma: allowlist secret
        timeout=10.0,
    )

    assert store.host == "postgres.local"
    assert store.port == 5433
    assert store.database == "test_db"
    assert store.user == "test_user"
    assert store.password == "test_pass"  # pragma: allowlist secret
    assert store.timeout == 10.0
    assert store._pool is None


def test_postgres_identity_store_defaults() -> None:
    store = PostgresIdentityStore()

    assert store.host == "localhost"
    assert store.port == 5432
    assert store.database == "aegis"
    assert store.user == "aegis_app"
    assert store.password == ""
    assert store.timeout == 5.0


def test_create_default_context_returns_tier2_fallback() -> None:
    context = PostgresIdentityStore._create_default_context("unknown-asset-123")

    assert context.asset_name == "unknown-asset-123"
    assert context.asset_criticality == "tier2"
    assert "no metadata found" in context.asset_description.lower()
    assert context.similar_incidents == []
    assert context.ueba.has_baseline is False
    assert context.ueba.baseline_description == "No baseline"
    assert context.ueba.associated_users == []
    assert context.ueba.normal_activity_window == "Unknown"
    assert context.ueba.recent_anomalies == []
    assert context.ueba.anomaly_score == 0.0


@pytest.mark.asyncio
async def test_close_when_pool_is_none_does_not_crash() -> None:
    store = PostgresIdentityStore()
    await store.close()  # Should not raise even when _pool is None


@pytest.mark.asyncio
async def test_get_asset_context_outside_context_manager_raises() -> None:
    store = PostgresIdentityStore()
    with pytest.raises(RuntimeError, match="used outside context manager"):
        await store.get_asset_context("test-asset")


@pytest.mark.asyncio
async def test_record_activity_outside_context_manager_raises() -> None:
    store = PostgresIdentityStore()
    with pytest.raises(RuntimeError, match="used outside context manager"):
        await store.record_activity("test-asset")


@pytest.mark.asyncio
async def test_index_asset_outside_context_manager_raises() -> None:
    store = PostgresIdentityStore()
    context = RagContext(
        asset_name="test",
        asset_criticality="tier2",
        asset_description="test",
        similar_incidents=[],
        ueba=store._create_default_context("test").ueba,
    )
    with pytest.raises(RuntimeError, match="used outside context manager"):
        await store.index_asset(context)
