"""Level-1 KPIs for the Gap 2 behavioral anomaly score (pure, no Pi).

Targets are PROVISIONAL — calibrate against the real project.
"""

from __future__ import annotations

from typing import Any

import pytest

from aegis.rag import ueba

pytestmark = pytest.mark.benchmark

# Provisional targets.
_SPIKE_MIN = 0.8  # a clear burst must score at least this
_REST_MAX = 0.1  # normal activity must score at most this


@pytest.mark.asyncio
async def test_anomaly_score_kpis(kpi_sink: dict[str, Any]) -> None:
    baseline = 4.0  # asset normally sees ~4 events / window

    # 1) At rest: recent activity at the baseline → ~0.
    rest = ueba.anomaly_score(recent_count=4, baseline=baseline)
    # 2) Spike: a clear burst (>= baseline * spike_factor) → saturates to 1.0.
    spike = ueba.anomaly_score(
        recent_count=int(baseline * ueba.DEFAULT_SPIKE_FACTOR), baseline=baseline
    )
    # 3) Bounds: across a wide sweep the score never leaves [0, 1].
    sweep = [
        ueba.anomaly_score(recent_count=c, baseline=b)
        for b in (0.0, 1.0, 4.0, 50.0)
        for c in (0, 1, 5, 20, 100, 10_000)
    ]
    bounds_ok = all(0.0 <= s <= 1.0 for s in sweep)

    # 4) Decay: a sustained high rate is absorbed by the EWMA baseline, so the
    #    score returns to ~0 even though activity stays elevated.
    high_rate = 12
    b = baseline
    decay_scores = []
    for _ in range(20):
        decay_scores.append(ueba.anomaly_score(recent_count=high_rate, baseline=b))
        b = ueba.update_baseline(b, high_rate)
    decayed = decay_scores[-1]

    kpi = {
        "rest_score": rest,
        "spike_score": spike,
        "bounds_ok": bounds_ok,
        "spike_then_decayed": decayed,
        "spike_peaked": decay_scores[0],
    }
    kpi_sink["anomaly"] = kpi

    assert rest <= _REST_MAX, f"rest score too high: {rest}"
    assert spike >= _SPIKE_MIN, f"spike score too low: {spike}"
    assert bounds_ok, f"score left [0,1]: {sweep}"
    assert decay_scores[0] >= _SPIKE_MIN, "initial spike should peak high"
    assert decayed <= _REST_MAX, f"sustained load should decay to normal, got {decayed}"


def test_prune_window_drops_old_events() -> None:
    now = 1000.0
    ts = [100.0, 700.0, 800.0, 999.0]  # window 300s -> keep >= 700
    kept = ueba.prune_window(ts, now=now, window_s=300.0)
    assert kept == [700.0, 800.0, 999.0]
