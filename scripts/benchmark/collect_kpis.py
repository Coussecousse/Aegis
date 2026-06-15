#!/usr/bin/env python3
"""Collect AEGIS KPIs over a run window and write a timestamped report.

Pulls latency/queue/SOAR KPIs from Prometheus and parses the middleware
container logs for pipeline-event counts, then writes
docs/benchmarks/report-<ts>.md (+ .json).

Example:
    python -m scripts.benchmark.collect_kpis --since <T0> --until <T1>
"""

from __future__ import annotations

import argparse
import json
import math
import os
import pathlib
import subprocess
from datetime import datetime
from typing import Any

from scripts.benchmark import promql

_REPORT_DIR = pathlib.Path(__file__).resolve().parents[2] / "docs" / "benchmarks"
_EVENTS = (
    "pipeline_start",
    "triage_escalated",
    "alert_discarded",
    "llm_complete",
    "llm_error",
    "report_generated",
)


def _window_expr(since_iso: str, until_iso: str) -> str:
    """Prometheus range-vector window covering [since, until], min 1m."""
    since = datetime.fromisoformat(since_iso)
    until = datetime.fromisoformat(until_iso)
    minutes = max(1, math.ceil((until - since).total_seconds() / 60))
    return f"{minutes}m"


def _collect_prometheus(prom_url: str, window: str, at_iso: str) -> dict[str, Any]:
    q = lambda expr: promql.scalar(promql.query_instant(prom_url, expr, at_iso))  # noqa: E731
    return {
        "mttt_triage_p50_s": q(promql.latency_quantile("triage", 0.50, window)),
        "mttt_triage_p95_s": q(promql.latency_quantile("triage", 0.95, window)),
        "slm_p95_s": q(promql.latency_quantile("slm", 0.95, window)),
        "rag_p95_s": q(promql.latency_quantile("rag", 0.95, window)),
        "llm_p95_s": q(promql.latency_quantile("llm", 0.95, window)),
        "triage_queue_peak": q(promql.queue_peak("aegis.triage", window)),
        "reports_queue_peak": q(promql.queue_peak("aegis.reports", window)),
        "soar_success_rate": q(promql.soar_success_rate(window)),
    }


def _collect_log_events(since_iso: str, container: str) -> dict[str, int]:
    counts = dict.fromkeys(_EVENTS, 0)
    try:
        out = subprocess.run(  # noqa: S603
            ["docker", "logs", "--since", since_iso, container],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        print(f"WARN could not read {container} logs: {exc}")
        return counts
    for line in (out.stdout + out.stderr).splitlines():
        for event in _EVENTS:
            if f'"event": "{event}"' in line:
                counts[event] += 1
    return counts


def _markdown(window: dict[str, Any], prom: dict[str, Any], events: dict[str, int]) -> str:
    escalated = events["triage_escalated"]
    completed = events["llm_complete"] + events["llm_error"]
    json_valid = (events["llm_complete"] / completed) if completed else None
    lines = [
        f"# AEGIS KPI report — {window['t0']} → {window['t1']}",
        "",
        f"- scenarios: `{window.get('scenarios')}` · intensity: `{window.get('intensity')}`",
        "",
        "## Latency / throughput (Prometheus)",
        "| KPI | value |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in prom.items()]
    lines += [
        "",
        "## Pipeline events (middleware logs)",
        "| event | count |",
        "|---|---|",
    ]
    lines += [f"| {k} | {v} |" for k, v in events.items()]
    lines += [
        "",
        "## Derived",
        f"- escalations: {escalated}",
        f"- LLM JSON-valid rate: {json_valid if json_valid is not None else 'n/a'}",
        f"- LLM errors/fallbacks: {events['llm_error']}",
        "",
        "_Provisional baseline — fill ADR 002 Results from a representative run._",
    ]
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS KPI collector")
    parser.add_argument("--since", required=True, help="run start (ISO 8601)")
    parser.add_argument("--until", required=True, help="run end (ISO 8601)")
    parser.add_argument("--prometheus", default=os.getenv("PROM_URL", "http://localhost:9090"))
    parser.add_argument("--container", default="aegis-node1-middleware-1")
    args = parser.parse_args()

    window = _window_expr(args.since, args.until)
    prom = _collect_prometheus(args.prometheus, window, args.until)
    events = _collect_log_events(args.since, args.container)
    window_meta = {"t0": args.since, "t1": args.until}

    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report = {"window": window_meta, "prometheus": prom, "events": events}
    (_REPORT_DIR / f"report-{stamp}.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    md = _markdown(window_meta, prom, events)
    (_REPORT_DIR / f"report-{stamp}.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Wrote docs/benchmarks/report-{stamp}.md (+ .json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
