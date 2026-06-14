"""Unit tests for deterministic remediation playbooks."""

from datetime import UTC, datetime
from uuid import uuid4

from aegis.middleware.models import WazuhLog
from aegis.middleware.playbooks import render_playbook_action


def _make_log(
    rule_id: int,
    full_log: str = "no request line here",
    attacker_ip: str | None = None,
    source_ip: str = "127.0.0.1",
) -> WazuhLog:
    return WazuhLog(
        id=uuid4(),
        timestamp=datetime.now(UTC),
        source_agent="node1-host",
        source_ip=source_ip,
        attacker_ip=attacker_ip,
        rule_id=rule_id,
        rule_level=10,
        rule_description="test",
        full_log=full_log,
        mitre_technique=None,
        decoder_name=None,
    )


def test_render_sqli_uses_attacker_ip_and_extracted_url() -> None:
    log = _make_log(
        31103,
        full_log='172.18.0.1 - - [..] "GET /rest/products/search?q=x HTTP/1.1" 500 994 "-" "curl"',
        attacker_ip="172.18.0.1",
    )
    action = render_playbook_action(log)
    assert action is not None
    assert "172.18.0.1" in action
    assert "/rest/products/search?q=x" in action


def test_render_falls_back_to_source_ip_when_no_attacker() -> None:
    log = _make_log(5710, attacker_ip=None, source_ip="10.0.0.9")
    action = render_playbook_action(log)
    assert action is not None
    assert "10.0.0.9" in action


def test_render_url_placeholder_when_no_request_line() -> None:
    log = _make_log(31103, full_log="no http line", attacker_ip="172.18.0.1")
    action = render_playbook_action(log)
    assert action is not None
    assert "the affected endpoint" in action


def test_render_custom_rule_action() -> None:
    action = render_playbook_action(_make_log(100011))
    assert action is not None
    assert "ransomware" in action.lower()


def test_render_returns_none_for_unknown_rule() -> None:
    assert render_playbook_action(_make_log(999999)) is None
