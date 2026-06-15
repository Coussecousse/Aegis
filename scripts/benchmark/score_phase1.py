#!/usr/bin/env python3
"""Score Phase-1 (quality) reports against the labeled corpus.

Reads the reports captured by report_sink.py (the real AegisReport JSON the Pi
produced) and grades them against ground truth: real recall, real false-positive
rate, severity accuracy, action specificity, attack-type relevance. All scoring
helpers are pure functions so they're unit-tested at Level 1 without a live run.

Targets are PROVISIONAL — calibrate against the real project.
"""

from __future__ import annotations

import argparse
import json
import pathlib
from typing import Any

_SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Scenario letter -> keywords that make an attack_type "relevant" (not generic).
_ATTACK_KEYWORDS: dict[str, tuple[str, ...]] = {
    "A": ("scan", "recon", "enumeration", "probe"),
    "B": ("sql", "injection"),
    "C": ("xss", "cross-site", "cross site", "script"),
    "D": ("traversal", "path", "lfi", "directory", "file inclusion"),
    "E": ("command", "injection", "rce", "execution"),
    "F": ("brute", "auth", "login", "password", "ssh"),
}


def load_jsonl(path: pathlib.Path) -> list[dict[str, Any]]:
    """Load newline-delimited JSON objects."""
    out: list[dict[str, Any]] = []
    if not path.exists():
        return out
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            out.append(json.loads(line))
    return out


def correlate(report: dict[str, Any], labels: dict[str, dict[str, Any]]) -> str | None:
    """Match a captured report to a corpus id by rule_id, disambiguated by URL."""
    src = report.get("source_log", {})
    rule_id = src.get("rule_id")
    full_log = src.get("full_log", "") or ""
    candidates = [cid for cid, lab in labels.items() if lab.get("expected_rule_id") == rule_id]
    if len(candidates) <= 1:
        return candidates[0] if candidates else None
    # Multiple labels share the rule id (e.g. 31103) — disambiguate by endpoint.
    for cid in candidates:
        url = labels[cid].get("expected_url")
        if url and url in full_log:
            return cid
    return candidates[0]


def severity_ok(report: dict[str, Any], floor: str | None) -> bool:
    """decision.severity >= the labeled floor (True when no floor is set)."""
    if not floor:
        return True
    actual = report.get("decision", {}).get("severity", "low")
    return _SEVERITY_RANK.get(actual, 0) >= _SEVERITY_RANK.get(floor, 0)


def action_specific(report: dict[str, Any], actor_ip: str | None, expected_url: str | None) -> bool:
    """recommended_action cites the real attacker IP and (if any) the endpoint."""
    action = report.get("decision", {}).get("recommended_action", "") or ""
    ip = actor_ip or report.get("source_log", {}).get("attacker_ip")
    ip_ok = bool(ip) and ip in action
    url_ok = (expected_url is None) or (expected_url in action)
    return ip_ok and url_ok


def attack_type_relevant(report: dict[str, Any], scenario: str) -> bool:
    """attack_type contains a keyword expected for the scenario family."""
    llm = report.get("llm_analysis")
    if not llm:
        return False
    attack_type = (llm.get("attack_type") or "").lower()
    keywords = _ATTACK_KEYWORDS.get(scenario[:1].upper(), ())
    return any(k in attack_type for k in keywords)


def summary_cites(report: dict[str, Any], actor_ip: str | None, expected_url: str | None) -> bool:
    """plain_language_summary mentions the actor IP or the endpoint."""
    llm = report.get("llm_analysis")
    if not llm:
        return False
    summary = llm.get("plain_language_summary") or ""
    ip = actor_ip or report.get("source_log", {}).get("attacker_ip")
    return (bool(ip) and ip in summary) or (expected_url is not None and expected_url in summary)


def score(
    reports: list[dict[str, Any]],
    labels: dict[str, dict[str, Any]],
    fired_scenarios: list[str],
    actor_ip: str | None,
) -> dict[str, Any]:
    """Aggregate Phase-1 KPIs from captured reports + the run manifest."""
    fired_attacks = {s for s in fired_scenarios if labels.get(s, {}).get("is_attack")}
    fired_benign = {s for s in fired_scenarios if not labels.get(s, {}).get("is_attack", True)}

    reported_ids = {correlate(r, labels) for r in reports}
    reported_ids.discard(None)

    attacks_detected = fired_attacks & reported_ids
    benign_reported = fired_benign & reported_ids

    quality = {
        "severity_ok": 0,
        "action_specific": 0,
        "attack_type_relevant": 0,
        "summary_cites": 0,
    }
    attack_reports = 0
    json_valid = 0
    details: list[dict[str, Any]] = []
    for report in reports:
        cid = correlate(report, labels)
        if cid is None or not labels[cid].get("is_attack"):
            continue
        attack_reports += 1
        lab = labels[cid]
        url = lab.get("expected_url")
        is_valid = report.get("llm_analysis") is not None
        checks = {
            "json_valid": is_valid,
            "severity_ok": severity_ok(report, lab.get("expected_min_severity")),
            "action_specific": action_specific(report, actor_ip, url),
            "attack_type_relevant": attack_type_relevant(report, lab.get("scenario", "")),
            "summary_cites": summary_cites(report, actor_ip, url),
        }
        json_valid += int(is_valid)
        for k in quality:
            quality[k] += int(checks[k])
        details.append({"corpus_id": cid, **checks})

    def rate(num: int, den: int) -> float | None:
        return round(num / den, 3) if den else None

    return {
        "fired_attacks": sorted(fired_attacks),
        "fired_benign": sorted(fired_benign),
        "real_recall": rate(len(attacks_detected), len(fired_attacks)),
        "real_fp_rate": rate(len(benign_reported), len(fired_benign)),
        "attack_reports": attack_reports,
        "json_valid_rate": rate(json_valid, attack_reports),
        "severity_accuracy": rate(quality["severity_ok"], attack_reports),
        "action_specificity": rate(quality["action_specific"], attack_reports),
        "attack_type_relevance": rate(quality["attack_type_relevant"], attack_reports),
        "summary_specificity": rate(quality["summary_cites"], attack_reports),
        "details": details,
    }


def _markdown(kpi: dict[str, Any], manifest: dict[str, Any]) -> str:
    rows = [
        ("Real recall", kpi["real_recall"], "≥ 0.90"),
        ("Real false-positive rate", kpi["real_fp_rate"], "≤ 0.10"),
        ("Report JSON-valid rate", kpi["json_valid_rate"], "≥ 0.95"),
        ("Severity accuracy", kpi["severity_accuracy"], "≥ 0.80"),
        ("Action specificity", kpi["action_specificity"], "≥ 0.80"),
        ("attack_type relevance", kpi["attack_type_relevance"], "≥ 0.70"),
        ("Summary specificity", kpi["summary_specificity"], "≥ 0.60"),
    ]
    lines = [
        f"# AEGIS Phase-1 (quality) report — {manifest.get('started', '?')}",
        "",
        f"- actor IP: `{manifest.get('actor_ip')}` · scenarios fired: "
        f"`{manifest.get('scenarios')}`",
        "",
        "| KPI | Measured | Target (provisional) |",
        "|---|---|---|",
    ]
    lines += [f"| {name} | {val} | {tgt} |" for name, val, tgt in rows]
    lines += ["", "_Targets are provisional — calibrate against the real project._"]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS Phase-1 quality scorer")
    parser.add_argument("--reports", default="/tmp/aegis-reports.jsonl")  # noqa: S108
    parser.add_argument("--manifest", default="/tmp/aegis-quality-manifest.json")  # noqa: S108
    _corpus = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/corpus/labels.json"
    parser.add_argument("--corpus", default=str(_corpus))
    args = parser.parse_args()

    labels = json.loads(pathlib.Path(args.corpus).read_text(encoding="utf-8"))
    reports = load_jsonl(pathlib.Path(args.reports))
    manifest = json.loads(pathlib.Path(args.manifest).read_text(encoding="utf-8"))

    kpi = score(reports, labels, manifest.get("scenarios", []), manifest.get("actor_ip"))

    out_dir = pathlib.Path(__file__).resolve().parents[2] / "docs" / "benchmarks"
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = str(manifest.get("started", "now")).replace(":", "").replace("-", "")[:15] or "now"
    (out_dir / f"report-quality-{stamp}.json").write_text(
        json.dumps({"manifest": manifest, "kpi": kpi}, indent=2), encoding="utf-8"
    )
    md = _markdown(kpi, manifest)
    (out_dir / f"report-quality-{stamp}.md").write_text(md, encoding="utf-8")
    print(md)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
