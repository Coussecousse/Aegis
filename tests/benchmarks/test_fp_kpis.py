"""Level-1 false-positive KPI: benign alerts must not reach the LLM.

A false positive here = a benign-but-alerting event (infra self-monitoring such
as netstat/dockerd) that AEGIS escalates to a full LLM report, burning a ~5-9 min
analysis cycle. Target: FP rate <= 5% once the production noise filter
(WAZUH_EXCLUDED_RULES) is applied; the run also records the rate WITHOUT the
filter to show how much infra noise the filter removes.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.benchmarks._kpi_harness import NOISE_FILTER, load_corpus, run_canonical

pytestmark = pytest.mark.benchmark

FP_RATE_TARGET = 0.05


async def _escalation_rate(excluded: frozenset[int]) -> tuple[int, int, list[str]]:
    benign = 0
    escalated = 0
    offenders: list[str] = []
    for cid, raw, label in load_corpus():
        if label["is_attack"]:
            continue
        benign += 1
        _, report = await run_canonical(raw, is_attack=False, excluded_rules=excluded)
        if report is not None:
            escalated += 1
            offenders.append(cid)
    return benign, escalated, offenders


@pytest.mark.asyncio
async def test_false_positive_rate(kpi_sink: dict[str, Any]) -> None:
    benign, fp_filtered, offenders = await _escalation_rate(NOISE_FILTER)
    _, fp_unfiltered, _ = await _escalation_rate(frozenset())

    rate_filtered = fp_filtered / benign if benign else 0.0
    rate_unfiltered = fp_unfiltered / benign if benign else 0.0

    kpi_sink["false_positives"] = {
        "benign_total": benign,
        "fp_with_noise_filter": fp_filtered,
        "fp_rate_with_filter": round(rate_filtered, 3),
        "fp_rate_without_filter": round(rate_unfiltered, 3),
        "target_max": FP_RATE_TARGET,
        "offenders_with_filter": offenders,
    }

    assert rate_filtered <= FP_RATE_TARGET, offenders
