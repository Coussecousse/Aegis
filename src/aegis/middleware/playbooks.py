"""Deterministic remediation playbooks keyed by Wazuh rule id.

For known attack classes the recommended action should not depend on the LLM
inventing it (weak 7B models copy examples or hallucinate steps like "disable
the account" on a SQL injection). Instead, compose the action from a vetted
template and the real fields extracted from the alert (attacker IP, target
host, request path). The LLM still writes the human-readable narrative
(``plain_language_summary``); only ``recommended_action`` is templated here.

Templates use ``{actor}`` (attacker IP, or the host IP when none is distinct),
``{host}`` (target host name) and ``{url}`` (request path from the log, when
present). The web/SSH entries are parameterised; the AEGIS custom rules
(100001-100042) carry the vetted procedures from
``docs/runbooks/wazuh-rules.md``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from aegis.middleware.models import WazuhLog

# First request path in a combined-format access log line: "GET /path?q=.. HTTP/1.1"
_REQUEST_PATH_RE = re.compile(r'"(?:GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+(\S+)\s+HTTP')


@dataclass(frozen=True)
class Playbook:
    """A vetted remediation action template for a Wazuh rule."""

    action_template: str


# rule_id -> Playbook. Web/SSH templates interpolate {actor}/{host}/{url};
# custom-rule entries are the documented procedures (no interpolation needed).
PLAYBOOKS: dict[int, Playbook] = {
    # --- Built-in web attacks (Juice Shop / nginx) ---
    31103: Playbook("Block {actor} at the firewall; audit {url} logs for SQL payloads."),
    31151: Playbook("Block {actor} at the firewall; review repeated 400s on {url} (scan)."),
    31152: Playbook("Block {actor}; audit {url} for SQLi and check the DB for tampering."),
    31153: Playbook("Block {actor} at the firewall; review {url} access logs for the pattern."),
    31154: Playbook("Block {actor}; sanitize/escape inputs on {url} to stop the XSS."),
    # --- Built-in SSH brute force ---
    5710: Playbook("Block {actor}; review auth logs on {host}, enforce key-based SSH."),
    5712: Playbook("Block {actor}; confirm no successful login from it on {host}."),
    # --- AEGIS custom rules (see docs/runbooks/wazuh-rules.md) ---
    100001: Playbook("Temporarily block {actor}; open an IAM investigation (AD failures)."),
    100002: Playbook("Force password reset, invalidate sessions, verify MFA."),
    100003: Playbook("Revert the Admins-group change, isolate the account, urgent AD review."),
    100004: Playbook("Verify the off-hours Tier 0 login on {host}; fix access policy."),
    100005: Playbook("Isolate {host}, block the admin account, activate crisis response."),
    100010: Playbook("Isolate {host}, disable the write share, start a ransomware hunt."),
    100011: Playbook("Immediately isolate {host}; trigger the ransomware response plan."),
    100012: Playbook("Freeze DB changes on {host}, check integrity, compare snapshots."),
    100013: Playbook("Isolate {host}, block the process, collect forensic artifacts."),
    100020: Playbook("Stop the outbound flow from {host}, validate dest, inspect the user."),
    100021: Playbook("Block network access for {host}, verify it, review VLAN ACLs."),
    100022: Playbook("Suspend the account; review queries and exfiltration (non-DBA dump)."),
    100030: Playbook("Close direct DB access from {host}; strengthen the DB bastion."),
    100031: Playbook("SOC blinding: prioritize isolation of {host}, investigate tampering."),
    100032: Playbook("Verify the change, audit sudo commands on {host}, fix permissions."),
    100040: Playbook("Verify the CAB ticket; roll back unauthorized software on {host}."),
    100041: Playbook("Block the destination; analyze traffic/process on {host} (C2)."),
    100042: Playbook("Block {actor}, rotate RabbitMQ credentials, audit API access."),
}


def _extract_request_path(full_log: str) -> str | None:
    """Return the first HTTP request path in a combined-format access log line."""
    match = _REQUEST_PATH_RE.search(full_log)
    return match.group(1) if match else None


def render_playbook_action(log: WazuhLog) -> str | None:
    """Render the deterministic remediation action for a log's rule, if any.

    Args:
        log: The Wazuh log whose rule_id selects the playbook.

    Returns:
        The composed action string, or None when no playbook covers the rule.
    """
    playbook = PLAYBOOKS.get(log.rule_id)
    if playbook is None:
        return None

    actor = log.attacker_ip or log.source_ip
    url = _extract_request_path(log.full_log) or "the affected endpoint"
    return playbook.action_template.format(actor=actor, host=log.source_agent, url=url)
