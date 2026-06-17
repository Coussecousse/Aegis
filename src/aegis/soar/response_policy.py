"""Human pre-approved response policies, keyed by Wazuh rule id (SOAR layer).

A response policy is a *standing human decision*: "for this Wazuh rule, take this
containment action". When an alert with a matching rule fires, AEGIS records the
action on the report (the actual execution is Shuffle's job) so the human is told,
as a fact, that a pre-defined response applies — tied to the rule code, not the LLM.

A policy may be:
- ``auto = true``  → pre-approved: the response may run without a per-incident click
  (``auto_remediation_allowed`` is set True). The human still receives the incident.
- ``auto = false`` → pre-staged: the response is proposed; a human confirms it in Shuffle.

Policies are operator-owned config, loaded from a JSON file. The default is **empty**
(no automatic action) so nothing ever fires unless a human explicitly opts in.

JSON shape (a list):
    [{"rule_id": 5712, "action": "Block {actor} at the firewall", "auto": true}, ...]
Templates may use ``{actor}`` (attacker IP, or host IP when none), ``{host}`` (asset
name) and ``{url}`` (request path, when present).
"""

from __future__ import annotations

import json
import logging
import pathlib
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ResponsePolicy:
    """A pre-defined containment action for a Wazuh rule."""

    rule_id: int
    action: str
    auto: bool


def load_policies(path: str | pathlib.Path | None) -> dict[int, ResponsePolicy]:
    """Load ``rule_id -> ResponsePolicy`` from a JSON file.

    Returns an empty map (no automatic action) when the path is unset, missing, or
    invalid — failing safe so a bad config never silently enables auto-remediation.
    """
    if not path:
        return {}
    file = pathlib.Path(path)
    if not file.exists():
        logger.warning(json.dumps({"event": "response_policy_missing", "path": str(file)}))
        return {}
    try:
        raw = json.loads(file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        logger.error(json.dumps({"event": "response_policy_invalid", "error": str(exc)}))
        return {}

    policies: dict[int, ResponsePolicy] = {}
    for item in raw if isinstance(raw, list) else []:
        if not isinstance(item, dict):
            continue
        try:
            rule_id = int(item["rule_id"])
            action = str(item["action"])
        except (KeyError, TypeError, ValueError):
            continue
        if not action:
            continue
        policies[rule_id] = ResponsePolicy(
            rule_id=rule_id, action=action, auto=bool(item.get("auto", False))
        )
    return policies


def render_action(policy: ResponsePolicy, *, actor: str, host: str, url: str | None) -> str:
    """Fill a policy's action template with the alert's real target fields."""
    return policy.action.format(actor=actor, host=host, url=url or "the affected endpoint")
