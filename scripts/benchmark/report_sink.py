#!/usr/bin/env python3
"""Capture AegisReports for Phase-1 (quality) scoring.

A tiny HTTP server that stands in for the Shuffle SOAR webhook: point
``SHUFFLE_WEBHOOK_URL`` at it during a quality run and every report the pipeline
delivers is appended (full JSON, one per line) to a capture file. Non-invasive —
it reuses the existing SOAR delivery path (`ShuffleClient.send_report`), so no
pipeline change is needed.

Run on the host, reachable from the middleware container:
    python -m scripts.benchmark.report_sink --port 8099 --out /tmp/aegis-reports.jsonl
    # then set, for the run:  SHUFFLE_WEBHOOK_URL=http://host.docker.internal:8099/
"""

from __future__ import annotations

import argparse
import json
import pathlib
import signal
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer
from types import FrameType

_OUT_PATH = pathlib.Path("/tmp/aegis-reports.jsonl")  # noqa: S108 — overridable via --out


class _Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 (http.server API)
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length) if length else b""
        ok = True
        try:
            obj = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            ok = False
            obj = {"_unparseable_body": raw.decode("utf-8", errors="replace")}
        with _OUT_PATH.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(obj) + "\n")
        alert = obj.get("alert_id", "?") if isinstance(obj, dict) else "?"
        print(f"  captured report alert_id={alert} ({'ok' if ok else 'unparseable'})")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'{"status":"captured"}')

    def log_message(self, *_: object) -> None:  # silence default access logging
        return


def main() -> int:
    global _OUT_PATH
    parser = argparse.ArgumentParser(description="AEGIS report capture sink")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--out", default=str(_OUT_PATH))
    parser.add_argument("--reset", action="store_true", help="truncate the capture file first")
    args = parser.parse_args()

    _OUT_PATH = pathlib.Path(args.out)
    if args.reset and _OUT_PATH.exists():
        _OUT_PATH.unlink()
    _OUT_PATH.parent.mkdir(parents=True, exist_ok=True)

    server = HTTPServer(("0.0.0.0", args.port), _Handler)  # noqa: S104 — reachable from container

    def _stop(_sig: int, _frame: FrameType | None) -> None:
        print("\nstopping report sink")
        server.shutdown()

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)
    print(f"report sink on :{args.port} → {_OUT_PATH} (Ctrl-C to stop)")
    server.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
