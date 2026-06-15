"""Unit tests for the Phase-1 quality scorer (pure functions, no live run)."""

from __future__ import annotations

from typing import Any

import pytest

from scripts.benchmark import score_phase1

pytestmark = pytest.mark.benchmark

_LABELS: dict[str, dict[str, Any]] = {
    "B-sqli": {
        "scenario": "B-sqli",
        "is_attack": True,
        "expected_rule_id": 31103,
        "expected_url": "/rest/products/search",
        "expected_min_severity": "high",
    },
    "E-cmd": {
        "scenario": "E-cmd-injection",
        "is_attack": True,
        "expected_rule_id": 31103,
        "expected_url": "/api/run",
        "expected_min_severity": "high",
    },
    "I-noise": {
        "scenario": "I-noise",
        "is_attack": False,
        "expected_rule_id": 533,
        "expected_url": None,
        "expected_min_severity": None,
    },
}


def _report(rule_id: int, url: str, ip: str, action: str, attack_type: str, summary: str) -> dict:
    return {
        "source_log": {"rule_id": rule_id, "attacker_ip": ip, "full_log": f"GET {url} HTTP/1.1"},
        "llm_analysis": {"attack_type": attack_type, "plain_language_summary": summary},
        "decision": {"severity": "high", "recommended_action": action},
    }


def test_correlate_disambiguates_shared_rule_id_by_url() -> None:
    sqli = _report(31103, "/rest/products/search?q=1", "1.1.1.1", "a", "t", "s")
    cmd = _report(31103, "/api/run?cmd=id", "1.1.1.1", "a", "t", "s")
    assert score_phase1.correlate(sqli, _LABELS) == "B-sqli"
    assert score_phase1.correlate(cmd, _LABELS) == "E-cmd"


def test_severity_ok_floor() -> None:
    assert score_phase1.severity_ok({"decision": {"severity": "critical"}}, "high")
    assert not score_phase1.severity_ok({"decision": {"severity": "medium"}}, "high")
    assert score_phase1.severity_ok({"decision": {"severity": "low"}}, None)


def test_action_specific_requires_ip_and_url() -> None:
    rpt = _report(
        31103,
        "/rest/products/search",
        "172.18.0.7",
        "Block 172.18.0.7; audit /rest/products/search",
        "t",
        "s",
    )
    assert score_phase1.action_specific(rpt, None, "/rest/products/search")
    assert not score_phase1.action_specific(rpt, None, "/other-endpoint")


def test_attack_type_relevance_and_summary() -> None:
    rpt = _report(
        31103,
        "/rest/products/search",
        "172.18.0.7",
        "a",
        "SQL injection attempt",
        "Host 172.18.0.7 sent SQL payloads.",
    )
    assert score_phase1.attack_type_relevant(rpt, "B-sqli")
    assert not score_phase1.attack_type_relevant(rpt, "C-xss")
    assert score_phase1.summary_cites(rpt, None, "/rest/products/search")


def test_score_aggregates_recall_fp_and_quality() -> None:
    good = _report(
        31103,
        "/rest/products/search",
        "172.18.0.7",
        "Block 172.18.0.7; audit /rest/products/search",
        "SQL injection",
        "Host 172.18.0.7 hit /rest/products/search",
    )
    kpi = score_phase1.score([good], _LABELS, ["B-sqli", "I-noise"], actor_ip=None)

    assert kpi["real_recall"] == 1.0  # 1 attack fired (B), 1 detected
    assert kpi["real_fp_rate"] == 0.0  # benign fired (I), none reported
    assert kpi["json_valid_rate"] == 1.0
    assert kpi["action_specificity"] == 1.0
    assert kpi["attack_type_relevance"] == 1.0
