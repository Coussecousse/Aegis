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


def _collect_resources(prom_url: str, window: str, at_iso: str) -> dict[str, Any]:
    """Raspberry Pi resource KPIs — None when node_exporter isn't scraped yet."""
    q = lambda expr: promql.scalar(promql.query_instant(prom_url, expr, at_iso))  # noqa: E731
    return {
        "pi_cpu_busy_pct": q(promql.pi_cpu_busy_pct(window)),
        "pi_mem_used_pct": q(promql.pi_mem_used_pct()),
        "pi_temp_celsius": q(promql.pi_temp_celsius()),
    }


def _count_wazuh_alerts(
    since_iso: str, until_iso: str, min_level: int, container: str
) -> int | None:
    """Count Wazuh alerts (level >= min) written in the window, via docker exec.

    Used for the zero-loss check: compare to how many alerts entered the pipeline
    (pipeline_start). Returns None if the container/file can't be read.
    """
    parser = (
        "import sys,json\n"
        "from datetime import datetime\n"
        f"s=datetime.fromisoformat({since_iso!r});u=datetime.fromisoformat({until_iso!r})\n"
        "n=0\n"
        "for ln in open('/var/ossec/logs/alerts/alerts.json','r',errors='replace'):\n"
        " ln=ln.strip()\n"
        " if not ln.startswith('{'):continue\n"
        " try:d=json.loads(ln)\n"
        " except Exception:continue\n"
        " ts=d.get('timestamp','')\n"
        " try:t=datetime.fromisoformat(ts.replace('+0000','+00:00'))\n"
        " except Exception:continue\n"
        f" if t>=s and t<=u and int(d.get('rule',{{}}).get('level',0))>={min_level}:n+=1\n"
        "print(n)\n"
    )
    try:
        out = subprocess.run(  # noqa: S603
            ["docker", "exec", container, "python3", "-c", parser],  # noqa: S607
            capture_output=True,
            text=True,
            timeout=60,
        )
        return int(out.stdout.strip())
    except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
        print(f"WARN could not count Wazuh alerts: {exc}")
        return None


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


def _markdown(
    window: dict[str, Any],
    prom: dict[str, Any],
    events: dict[str, int],
    resources: dict[str, Any] | None,
    loss: dict[str, Any] | None,
) -> str:
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
    if loss is not None:
        lines += [
            "",
            "## Zero-loss check (Phase 2)",
            "| metric | value |",
            "|---|---|",
            f"| Wazuh alerts (level>=min) in window | {loss['wazuh_alerts']} |",
            f"| entered pipeline (pipeline_start) | {loss['pipeline_starts']} |",
            f"| alerts lost | {loss['lost']} |",
        ]
    if resources is not None:
        lines += [
            "",
            "## Pi resources (node_exporter — None if not wired)",
            "| KPI | value |",
            "|---|---|",
        ]
        lines += [f"| {k} | {v} |" for k, v in resources.items()]
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
    parser.add_argument("--check-loss", action="store_true", help="zero-loss check (Phase 2)")
    parser.add_argument("--wazuh-container", default="aegis-node1-wazuh.manager-1")
    parser.add_argument("--min-level", type=int, default=7)
    parser.add_argument("--resources", action="store_true", help="collect Pi resource KPIs")
    args = parser.parse_args()

    window = _window_expr(args.since, args.until)
    prom = _collect_prometheus(args.prometheus, window, args.until)
    events = _collect_log_events(args.since, args.container)
    window_meta = {"t0": args.since, "t1": args.until}

    loss: dict[str, Any] | None = None
    if args.check_loss:
        wazuh = _count_wazuh_alerts(args.since, args.until, args.min_level, args.wazuh_container)
        if wazuh is not None:
            starts = events["pipeline_start"]
            loss = {
                "wazuh_alerts": wazuh,
                "pipeline_starts": starts,
                "lost": max(0, wazuh - starts),
            }

    resources: dict[str, Any] | None = None
    if args.resources or args.check_loss:
        resources = _collect_resources(args.prometheus, window, args.until)

    _REPORT_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    report = {
        "window": window_meta,
        "prometheus": prom,
        "events": events,
        "loss": loss,
        "resources": resources,
    }
    (_REPORT_DIR / f"report-{stamp}.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8"
    )
    md = _markdown(window_meta, prom, events, resources, loss)
    (_REPORT_DIR / f"report-{stamp}.md").write_text(md, encoding="utf-8")
    print(md)
    print(f"Wrote docs/benchmarks/report-{stamp}.md (+ .json)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
