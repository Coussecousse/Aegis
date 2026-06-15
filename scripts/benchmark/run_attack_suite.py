#!/usr/bin/env python3
"""Replay AEGIS attack scenarios against the live target (Level-2 KPI harness).

Purges the triage/reports queues, records the run window [T0, T1], fires the
selected scenarios (web requests always; external Kali tools when present), and
prints the window so collect_kpis.py can compute KPIs over it.

Examples:
    python -m scripts.benchmark.run_attack_suite --scenario all --intensity standard
    python -m scripts.benchmark.run_attack_suite --scenario B --intensity smoke
    python -m scripts.benchmark.run_attack_suite --scenario all --intensity soak
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import pathlib
import shutil
import subprocess
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime

from scripts.benchmark import scenarios

_CORPUS_LABELS = pathlib.Path(__file__).resolve().parents[2] / "tests/fixtures/corpus/labels.json"


def _attack_corpus_ids(letters: list[str]) -> list[str]:
    """Corpus attack ids whose scenario family matches the fired scenario letters."""
    try:
        labels = json.loads(_CORPUS_LABELS.read_text(encoding="utf-8"))
    except OSError:
        return []
    wanted = {ltr.upper() for ltr in letters}
    return [
        cid
        for cid, lab in labels.items()
        if lab.get("is_attack") and lab.get("scenario", "")[:1].upper() in wanted
    ]


def _purge_queues() -> None:
    """Best-effort purge of aegis.triage / aegis.reports via the RabbitMQ API."""
    user = os.getenv("RABBITMQ_USER", "guest")
    password = os.getenv("RABBITMQ_PASSWORD", "guest")
    mgmt = os.getenv("RABBITMQ_MGMT_URL", "http://localhost:15672")
    for queue in ("aegis.reports", "aegis.triage"):
        url = f"{mgmt}/api/queues/aegis/{queue}/contents"
        req = urllib.request.Request(url, method="DELETE")
        token = base64.b64encode(f"{user}:{password}".encode()).decode()
        req.add_header("Authorization", f"Basic {token}")
        try:
            urllib.request.urlopen(req, timeout=5)
            print(f"  purged {queue}")
        except urllib.error.URLError as exc:
            print(f"  WARN could not purge {queue}: {exc}")


def _fire(url: str) -> None:
    try:
        urllib.request.urlopen(url, timeout=10)
    except urllib.error.HTTPError:
        pass  # 4xx/5xx are expected for attack payloads — the alert still fires
    except urllib.error.URLError as exc:
        print(f"  WARN request failed {url}: {exc}")


def _fire_web(requests: list[str], intensity: str) -> None:
    print(f"  firing {len(requests)} web requests...")
    if intensity == "soak":
        loops = scenarios.SOAK_LOOPS
        with ThreadPoolExecutor(max_workers=scenarios.SOAK_PARALLELISM) as pool:
            for _ in range(loops):
                list(pool.map(_fire, requests))
    else:
        for url in requests:
            _fire(url)
            time.sleep(0.2)


def _run_tools(commands: list[list[str]]) -> None:
    for argv in commands:
        binary = argv[0]
        if shutil.which(binary) is None:
            print(f"  SKIP tool '{binary}' (not installed)")
            continue
        print(f"  running tool: {' '.join(argv)}")
        try:
            subprocess.run(argv, timeout=180, check=False)  # noqa: S603
        except (subprocess.TimeoutExpired, OSError) as exc:
            print(f"  WARN tool {binary} failed: {exc}")


def main() -> int:
    parser = argparse.ArgumentParser(description="AEGIS attack-scenario replayer")
    parser.add_argument("--scenario", default="all", help="all | comma-separated ids (A..F)")
    parser.add_argument("--intensity", default="standard", choices=("smoke", "standard", "soak"))
    parser.add_argument(
        "--base-url", default=os.getenv("BENCH_TARGET_URL", "http://localhost:9080")
    )
    parser.add_argument("--host", default=os.getenv("BENCH_TARGET_HOST", "localhost"))
    parser.add_argument("--no-purge", action="store_true")
    parser.add_argument("--no-tools", action="store_true", help="skip external Kali tools")
    parser.add_argument("--phase", choices=("raw", "quality", "load"), default="raw")
    parser.add_argument("--manifest", default="/tmp/aegis-bench-manifest.json")  # noqa: S108
    parser.add_argument("--actor-ip", default=None, help="override the attacker IP for scoring")
    args = parser.parse_args()

    ids = (
        list(scenarios.ALL_SCENARIO_IDS)
        if args.scenario == "all"
        else [s.strip().upper() for s in args.scenario.split(",") if s.strip()]
    )

    if not args.no_purge:
        print("Purging queues...")
        _purge_queues()

    run = scenarios.resolve(ids, args.base_url, args.host, args.intensity)
    t0 = datetime.now(UTC)
    print(f"T0={t0.isoformat()} scenarios={ids} intensity={args.intensity}")

    _fire_web(run.web_requests, args.intensity)
    if not args.no_tools:
        _run_tools(run.tool_commands)

    t1 = datetime.now(UTC)
    window = {
        "t0": t0.isoformat(),
        "t1": t1.isoformat(),
        "scenarios": ids,
        "intensity": args.intensity,
    }
    print(f"T1={t1.isoformat()}")
    print("WINDOW " + json.dumps(window))

    if args.phase != "raw":
        manifest = {
            "phase": args.phase,
            "started": t0.isoformat(),
            "ended": t1.isoformat(),
            "actor_ip": args.actor_ip,
            "web_requests_fired": len(run.web_requests),
            # For quality scoring: corpus attack ids matching the fired scenarios.
            "scenarios": _attack_corpus_ids(ids),
            "scenario_letters": ids,
        }
        pathlib.Path(args.manifest).write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"MANIFEST written to {args.manifest}")
        if args.phase == "quality":
            print("Next: python -m scripts.benchmark.score_phase1 " f"--manifest '{args.manifest}'")
        else:
            print(
                "Next: python -m scripts.benchmark.collect_kpis "
                f"--since '{t0.isoformat()}' --until '{t1.isoformat()}' --check-loss"
            )
    else:
        print(
            "\nNext: python -m scripts.benchmark.collect_kpis "
            f"--since '{t0.isoformat()}' --until '{t1.isoformat()}'"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
