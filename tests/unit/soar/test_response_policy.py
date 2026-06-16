"""Unit tests for the SOAR response-policy loader and renderer."""

from __future__ import annotations

import json
import pathlib

from aegis.soar.response_policy import ResponsePolicy, load_policies, render_action


def _write(tmp_path: pathlib.Path, data: object) -> pathlib.Path:
    f = tmp_path / "policies.json"
    f.write_text(json.dumps(data), encoding="utf-8")
    return f


def test_load_policies_parses_valid_entries(tmp_path: pathlib.Path) -> None:
    path = _write(
        tmp_path,
        [
            {"rule_id": 5712, "action": "Block {actor} at the firewall", "auto": True},
            {"rule_id": 31103, "action": "Audit {url} for SQLi"},  # auto defaults to False
        ],
    )
    policies = load_policies(path)

    assert set(policies) == {5712, 31103}
    assert policies[5712] == ResponsePolicy(5712, "Block {actor} at the firewall", auto=True)
    assert policies[31103].auto is False


def test_load_policies_skips_malformed_entries(tmp_path: pathlib.Path) -> None:
    path = _write(
        tmp_path,
        [
            {"rule_id": 5712, "action": "Block {actor}"},
            {"rule_id": "not-int", "action": "x"},  # bad rule_id
            {"action": "no rule id"},  # missing rule_id
            {"rule_id": 99, "action": ""},  # empty action
            "not-a-dict",
        ],
    )
    policies = load_policies(path)

    assert set(policies) == {5712}


def test_load_policies_failsafe_on_missing_or_unset_or_invalid(tmp_path: pathlib.Path) -> None:
    assert load_policies(None) == {}
    assert load_policies(tmp_path / "does-not-exist.json") == {}
    bad = tmp_path / "bad.json"
    bad.write_text("{ not json", encoding="utf-8")
    assert load_policies(bad) == {}


def test_render_action_fills_target_fields() -> None:
    policy = ResponsePolicy(31103, "Block {actor}; audit {url} on {host}", auto=False)
    rendered = render_action(
        policy, actor="172.20.0.1", host="node1-host", url="/rest/products/search"
    )
    assert rendered == "Block 172.20.0.1; audit /rest/products/search on node1-host"


def test_render_action_defaults_url_when_absent() -> None:
    policy = ResponsePolicy(5712, "Block {actor}; review {url}", auto=True)
    rendered = render_action(policy, actor="10.0.0.50", host="dc-01", url=None)
    assert "the affected endpoint" in rendered
