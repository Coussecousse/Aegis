"""Unit tests for Wazuh alert parser and RabbitMQ forwarder."""

from __future__ import annotations

from typing import Any

import pytest

from aegis.collectors.wazuh_forwarder import WazuhAlertParser, WazuhForwarder


def _valid_alert() -> dict[str, Any]:
    return {
        "timestamp": "2026-05-21T10:00:00+0000",
        "rule": {
            "id": "5710",
            "level": 10,
            "description": "SSH brute force",
        },
        "agent": {
            "name": "pi-test",
            "ip": "192.168.1.100",
        },
        "full_log": "test log",
        "decoder": {"name": "sshd"},
    }


def test_parse_alert_valid() -> None:
    parsed = WazuhAlertParser.parse_alert(_valid_alert(), min_level=7)

    assert parsed is not None
    assert parsed.rule_id == 5710
    assert parsed.rule_level == 10
    assert parsed.source_agent == "pi-test"
    assert parsed.source_ip == "192.168.1.100"
    assert parsed.decoder_name == "sshd"


def test_parse_alert_with_mitre() -> None:
    payload = _valid_alert()
    payload["mitre"] = {"technique": ["T1110", "T1021"]}

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is not None
    assert parsed.mitre_technique == "T1110"


def test_parse_alert_missing_fields_returns_none() -> None:
    payload = _valid_alert()
    del payload["rule"]

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is None


def test_parse_alert_below_min_level_returns_none() -> None:
    payload = _valid_alert()
    payload["rule"]["level"] = 6

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is None


def test_parse_alert_excluded_agent_returns_none() -> None:
    payload = _valid_alert()

    parsed = WazuhAlertParser.parse_alert(
        payload, min_level=7, excluded_agents=frozenset({"pi-test"})
    )

    assert parsed is None


def test_parse_alert_non_excluded_agent_passes() -> None:
    payload = _valid_alert()

    parsed = WazuhAlertParser.parse_alert(
        payload, min_level=7, excluded_agents=frozenset({"node1-host"})
    )

    assert parsed is not None
    assert parsed.source_agent == "pi-test"


@pytest.mark.asyncio
async def test_forwarder_publishes_to_exchange() -> None:
    published: list[str] = []

    class _FakeExchange:
        async def publish(self, message: object, routing_key: str) -> None:
            _ = message
            published.append(routing_key)

    forwarder = WazuhForwarder(min_level=7)
    forwarder._exchange = _FakeExchange()  # noqa: SLF001

    sent = await forwarder.forward_alert(_valid_alert())

    assert sent is True
    assert published == ["alert.raw"]
