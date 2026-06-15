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


def test_parse_alert_attacker_ip_from_data_srcip() -> None:
    payload = _valid_alert()
    payload["data"] = {"srcip": "172.18.0.1"}

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is not None
    assert parsed.source_ip == "192.168.1.100"  # asset/host (agent.ip) unchanged
    assert parsed.attacker_ip == "172.18.0.1"  # real actor surfaced


def test_parse_alert_attacker_ip_none_when_absent_or_same() -> None:
    # No data.srcip → no distinct actor.
    parsed = WazuhAlertParser.parse_alert(_valid_alert(), min_level=7)
    assert parsed is not None
    assert parsed.attacker_ip is None

    # data.srcip equal to the agent IP → not a distinct actor.
    payload = _valid_alert()
    payload["data"] = {"srcip": "192.168.1.100"}
    parsed_same = WazuhAlertParser.parse_alert(payload, min_level=7)
    assert parsed_same is not None
    assert parsed_same.attacker_ip is None


def test_parse_alert_with_mitre() -> None:
    payload = _valid_alert()
    payload["mitre"] = {"technique": ["T1110", "T1021"]}

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is not None
    assert parsed.mitre_technique == "T1110"


def test_parse_alert_excluded_rule_returns_none() -> None:
    payload = _valid_alert()
    payload["rule"]["id"] = "533"

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7, excluded_rules=frozenset({533}))

    assert parsed is None


def test_parse_alert_non_excluded_rule_passes() -> None:
    # Same agent/level, a rule that is not in the exclusion set still forwards —
    # proving the filter is scoped by rule, not by agent (no detection blackout).
    parsed = WazuhAlertParser.parse_alert(
        _valid_alert(), min_level=7, excluded_rules=frozenset({533})
    )

    assert parsed is not None
    assert parsed.rule_id == 5710


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


def test_parse_alert_dockerd_promiscuous_mode_returns_none() -> None:
    payload = _valid_alert()
    payload["rule"]["id"] = "80710"
    payload["full_log"] = (
        "type=ANOM_PROMISCUOUS msg=audit(1234567890.123:456): dev=veth9c3b5fc "
        "prom=256 old_prom=0 auid=4294967295 uid=0 gid=0 ses=4294967295 "
        'comm="dockerd" exe="/usr/bin/dockerd"'
    )

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is None


def test_parse_alert_promiscuous_mode_from_other_process_passes() -> None:
    payload = _valid_alert()
    payload["rule"]["id"] = "80710"
    payload["full_log"] = (
        "type=ANOM_PROMISCUOUS msg=audit(1234567890.123:456): dev=eth0 "
        "prom=256 old_prom=0 auid=1000 uid=0 gid=0 ses=3 "
        'comm="python3" exe="/usr/bin/python3"'
    )

    parsed = WazuhAlertParser.parse_alert(payload, min_level=7)

    assert parsed is not None
    assert parsed.rule_id == 80710


@pytest.mark.asyncio
async def test_forwarder_publishes_persistent_to_exchange() -> None:
    import aio_pika

    published: list[tuple[str, object]] = []

    class _FakeExchange:
        async def publish(self, message: object, routing_key: str) -> None:
            published.append((routing_key, message))

    forwarder = WazuhForwarder(min_level=7)
    forwarder._exchange = _FakeExchange()  # noqa: SLF001

    sent = await forwarder.forward_alert(_valid_alert())

    assert sent is True
    assert [rk for rk, _ in published] == ["alert.raw"]
    # An escalated/raw alert must survive a broker restart — published persistent.
    assert published[0][1].delivery_mode == aio_pika.DeliveryMode.PERSISTENT
