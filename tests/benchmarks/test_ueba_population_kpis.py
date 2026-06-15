"""Population-based UEBA KPIs (Level-1, deterministic).

These measure *rates over a population*, not single-case pass/fail:
- sync coverage: of N directory assets, how many end up profiled in UEBA;
- tier correctness: of those, how many carry the right criticality;
- identity-attack detection: of the corpus identity attacks (custom rules
  100xxx), how many are escalated by triage.

Targets are PROVISIONAL — calibrate against the real project.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.middleware.models import RagContext, UEBAMetrics
from aegis.rag import client as rag_client_module
from aegis.rag.base import BaseIdentityConnector
from aegis.rag.client import ChromaDBClient

from ._kpi_harness import load_corpus, run_canonical

pytestmark = pytest.mark.benchmark

# Provisional targets.
_COVERAGE_TARGET = 1.0
_TIER_TARGET = 1.0
_DETECTION_TARGET = 1.0

# A representative identity-store population (mirrors the seeded LDAP tiers):
# domain controllers / PKI are tier0, the rest tier2.
_POPULATION: dict[str, str] = {
    "DC-01": "tier0",
    "DC-02": "tier0",
    "PKI-01": "tier0",
    "WS-FACTORY-12": "tier2",
    "APP-ERP-01": "tier2",
    "NAS-ENG-01": "tier2",
}


class _PopulationConnector(BaseIdentityConnector):
    """Returns a per-asset identity context from a fixed population."""

    def __init__(self, population: dict[str, str]) -> None:
        self._population = population

    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        tier = self._population[asset_identifier]
        return RagContext(
            asset_name=asset_identifier,
            asset_criticality=tier,  # type: ignore[arg-type]
            asset_description="from directory",
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description="Identity baseline",
                associated_users=[],
                normal_activity_window="Unknown",
                recent_anomalies=[],
                anomaly_score=0.0,
            ),
        )


class _MultiCollection:
    """In-memory Chroma collection keyed by id (faithful get/upsert by id)."""

    def __init__(self) -> None:
        self.store: dict[str, dict[str, Any]] = {}

    async def get(self, ids: list[str]) -> dict[str, Any]:
        return {"metadatas": [self.store[i] for i in ids if i in self.store]}

    async def upsert(
        self, ids: list[str], metadatas: list[dict[str, Any]], embeddings: list[list[float]]
    ) -> None:
        _ = embeddings
        for asset_id, meta in zip(ids, metadatas, strict=False):
            self.store[asset_id] = meta


class _MultiChromaClient:
    def __init__(self, collection: _MultiCollection) -> None:
        self._collection = collection

    async def get_or_create_collection(self, name: str) -> _MultiCollection:
        _ = name
        return self._collection


class _MultiChromaModule:
    def __init__(self, collection: _MultiCollection) -> None:
        self._collection = collection

    async def AsyncHttpClient(self, host: str, port: int) -> _MultiChromaClient:  # noqa: N802
        _ = (host, port)
        return _MultiChromaClient(self._collection)


@pytest.mark.asyncio
async def test_sync_coverage_and_tier_correctness_kpis(
    kpi_sink: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    collection = _MultiCollection()
    monkeypatch.setattr(
        rag_client_module, "_get_chromadb_module", lambda: _MultiChromaModule(collection)
    )
    connector = _PopulationConnector(_POPULATION)

    profiled = 0
    correct_tier = 0
    total = len(_POPULATION)
    async with ChromaDBClient(host="chromadb", port=8000) as client:
        for asset_id in _POPULATION:
            await client.sync_asset_identity(asset_id, connector)
        for asset_id, expected_tier in _POPULATION.items():
            ctx = await client.get_asset_context(asset_id)
            if ctx.ueba.has_baseline:
                profiled += 1
            if ctx.asset_criticality == expected_tier:
                correct_tier += 1

    coverage = round(profiled / total, 3)
    tier_correctness = round(correct_tier / total, 3)
    kpi_sink["ueba_sync"] = {
        "population": total,
        "coverage": coverage,
        "tier_correctness": tier_correctness,
    }

    assert coverage >= _COVERAGE_TARGET, f"sync coverage {coverage} < {_COVERAGE_TARGET}"
    assert tier_correctness >= _TIER_TARGET, f"tier correctness {tier_correctness}"


@pytest.mark.asyncio
async def test_identity_attack_detection_kpi(kpi_sink: dict[str, Any]) -> None:
    # Identity-tied attacks in the corpus = the AEGIS custom rules (scenario "J-...").
    identity_attacks = [
        (cid, raw)
        for cid, raw, label in load_corpus()
        if label.get("is_attack") and label.get("scenario", "").startswith("J")
    ]
    assert identity_attacks, "corpus has no identity attacks to measure"

    detected = 0
    for _cid, raw in identity_attacks:
        _, report = await run_canonical(raw, is_attack=True)
        if report is not None:
            detected += 1

    rate = round(detected / len(identity_attacks), 3)
    kpi_sink["ueba_detection"] = {
        "identity_attacks": len(identity_attacks),
        "detected": detected,
        "detection_rate": rate,
    }

    assert rate >= _DETECTION_TARGET, f"identity-attack detection {rate} < {_DETECTION_TARGET}"
