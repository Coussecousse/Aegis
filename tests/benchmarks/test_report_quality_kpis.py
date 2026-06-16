"""Level-1 report-quality KPIs over the labeled corpus (deterministic)."""

from __future__ import annotations

from typing import Any

import pytest

from tests.benchmarks._kpi_harness import load_corpus, run_canonical, severity_ge

pytestmark = pytest.mark.benchmark


@pytest.mark.asyncio
async def test_report_quality_kpis(kpi_sink: dict[str, Any]) -> None:
    kpi = {
        "total_attacks": 0,
        "escalated": 0,
        "json_valid": 0,  # LLM analysis present (no SLM-only fallback)
        "action_specific": 0,  # recommended_action contains the real IP/endpoint
        "severity_ok": 0,  # decision.severity >= expected floor
        "failures": [],
    }

    for cid, raw, label in load_corpus():
        if not label["is_attack"]:
            continue
        kpi["total_attacks"] += 1

        _, report = await run_canonical(raw, is_attack=True)
        if report is None:
            kpi["failures"].append(f"{cid}: did not escalate / no report")
            continue
        kpi["escalated"] += 1

        if report.llm_analysis is not None:
            kpi["json_valid"] += 1

        action = report.decision.recommended_action
        if all(sub in action for sub in label["expected_action_contains"]):
            kpi["action_specific"] += 1
        else:
            want = label["expected_action_contains"]
            kpi["failures"].append(f"{cid}: action lacks {want}: {action!r}")

        floor = label["expected_min_severity"]
        if floor and severity_ge(report.decision.severity, floor):
            kpi["severity_ok"] += 1
        else:
            kpi["failures"].append(f"{cid}: severity {report.decision.severity} < {floor}")

    kpi_sink["report_quality"] = kpi

    n = kpi["total_attacks"]
    assert kpi["escalated"] == n, kpi["failures"]
    assert kpi["json_valid"] == n, kpi["failures"]
    assert kpi["action_specific"] == n, kpi["failures"]
    assert kpi["severity_ok"] == n, kpi["failures"]
