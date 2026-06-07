"""Collector entrypoint for forwarding Wazuh alerts into RabbitMQ."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from aegis.collectors.wazuh_forwarder import WazuhForwarder

logger = logging.getLogger(__name__)


def _build_forwarder_from_env() -> WazuhForwarder:
    """Build a ``WazuhForwarder`` using environment configuration."""
    return WazuhForwarder(
        rabbitmq_host=os.getenv("RABBITMQ_HOST", "localhost"),
        rabbitmq_port=int(os.getenv("RABBITMQ_PORT", "5672")),
        rabbitmq_user=os.getenv("RABBITMQ_USER", "guest"),
        rabbitmq_password=os.getenv("RABBITMQ_PASSWORD", "guest"),
        rabbitmq_vhost=os.getenv("RABBITMQ_VHOST", "aegis"),
        exchange_name="aegis.alerts",
        routing_key="alert.raw",
        min_level=int(os.getenv("WAZUH_MIN_LEVEL", "7")),
    )


def _iter_alerts_from_json_file(file_path: Path) -> list[dict[str, Any]]:
    """Load one or many JSON alerts from a Wazuh integration file."""
    content = file_path.read_text(encoding="utf-8").strip()
    if not content:
        return []

    payload = json.loads(content)
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        return [payload]
    return []


async def _run_integration_mode(alert_file: Path) -> int:
    """Forward alerts from one temporary Wazuh integration JSON file."""
    if not alert_file.exists():
        logger.error("Alert file does not exist: %s", alert_file)
        return 1

    forwarder = _build_forwarder_from_env()
    forwarded = 0

    await forwarder.connect()
    try:
        for payload in _iter_alerts_from_json_file(alert_file):
            if await forwarder.forward_alert(payload):
                forwarded += 1
    finally:
        await forwarder.close()

    logger.info("Integration mode complete: forwarded=%s", forwarded)
    return 0


async def _run_daemon_mode() -> int:
    """Tail alerts.json by polling and forward each new JSON line."""
    alerts_file = Path(os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"))
    poll_interval = float(os.getenv("WAZUH_POLL_INTERVAL", "1.0"))

    forwarder = _build_forwarder_from_env()
    await forwarder.connect()

    logger.info("Daemon mode started: file=%s poll_interval=%s", alerts_file, poll_interval)

    position = 0
    try:
        while True:
            if not alerts_file.exists():
                await asyncio.sleep(poll_interval)
                continue

            if alerts_file.stat().st_size < position:
                position = 0

            with alerts_file.open("r", encoding="utf-8", errors="replace") as handle:
                handle.seek(position)
                lines = handle.readlines()
                position = handle.tell()

            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(payload, dict):
                    await forwarder.forward_alert(payload)

            await asyncio.sleep(poll_interval)
    except KeyboardInterrupt:
        logger.info("Collector daemon interrupted")
        return 0
    finally:
        await forwarder.close()


def _parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="AEGIS Wazuh collector")
    parser.add_argument("alert_file", nargs="?", help="Wazuh temporary JSON file path")
    parser.add_argument("api_key", nargs="?", help="Unused Wazuh integration positional arg")
    parser.add_argument("hook_url", nargs="?", help="Unused Wazuh integration positional arg")
    parser.add_argument("--daemon", action="store_true", help="Run daemon mode")
    return parser.parse_args()


async def _async_main() -> int:
    """Run selected collector mode from CLI arguments."""
    args = _parse_args()
    if args.daemon:
        return await _run_daemon_mode()

    if not args.alert_file:
        logger.error("Missing alert_file argument. Use --daemon or provide a file path.")
        return 2

    return await _run_integration_mode(Path(args.alert_file))


def main() -> int:
    """Synchronous process entrypoint."""
    load_dotenv()
    logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO").upper())
    return asyncio.run(_async_main())


if __name__ == "__main__":
    raise SystemExit(main())
