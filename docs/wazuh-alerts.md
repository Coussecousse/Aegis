# AEGIS — Wazuh Alerts

How AEGIS ingests Wazuh alerts: the raw format, the fields it relies on, and the
filtering applied before an alert ever reaches the AI pipeline. For the *detection
rules* that produce these alerts, see [runbooks/wazuh-rules.md](runbooks/wazuh-rules.md).

## Where alerts come from

The Wazuh Manager writes JSON alerts to `/var/ossec/logs/alerts/alerts.json` (one
object per line). The AEGIS **collector**
([`collectors/__main__.py`](../src/aegis/collectors/__main__.py)) tails that file and
the **parser** ([`wazuh_forwarder.py`](../src/aegis/collectors/wazuh_forwarder.py))
maps each object to a `WazuhLog`, then publishes it (persistent) to `aegis.triage`.

## Raw alert → `WazuhLog`

A Wazuh alert is large; AEGIS keeps only what the pipeline needs:

| `WazuhLog` field | Source in the raw alert | Notes |
|---|---|---|
| `rule_id` | `rule.id` | The fired rule (e.g. `31103` SQLi). |
| `rule_level` | `rule.level` | Wazuh severity 0–15. |
| `rule_description` | `rule.description` | Human label of the rule. |
| `source_agent` | `agent.name` | The **monitored host** (the asset). |
| `source_ip` | `agent.ip` (fallback `data.srcip`) | The asset identity used for **RAG/UEBA lookup**. |
| `attacker_ip` | `data.srcip` (only if ≠ `agent.ip`) | The **remote actor** — surfaced so reports cite the attacker, not the host. |
| `full_log` | `full_log` | The raw event line (the LLM reasons from this). |
| `mitre_technique` | `rule.mitre.technique` (first) | Optional. |
| `decoder_name` | `decoder.name` | e.g. `web-accesslog`, `windows-eventlog`. |

> **Key distinction:** `source_ip` = the protected asset (for UEBA context);
> `attacker_ip` = the external client (for the remediation). On a web attack proxied
> through nginx the asset is the host and the attacker is the real client IP.

## Filtering before the pipeline (the parser drops these)

An alert is **not** forwarded when:

1. required fields are missing/empty (`rule.id`, `rule.level`, `rule.description`,
   `agent.name`, an IP, `full_log`);
2. `rule.level < WAZUH_MIN_LEVEL` (default tuned so web attacks at level 6 pass);
3. it is `dockerd` promiscuous-mode noise (rule `80710` with `comm="dockerd"`);
4. it is a Wazuh **operational** rule (agent lifecycle, not a security event);
5. its `rule.id` is in `WAZUH_EXCLUDED_RULES` (operator-configured noise list).

Everything else enters triage, where the SLM + UEBA gates decide escalate vs discard
(see [middleware.md](middleware.md)).

## Example (trimmed)

```json
{
  "timestamp": "2026-06-15T14:42:06Z",
  "rule": { "id": 31103, "level": 7, "description": "SQL injection attempt." },
  "agent": { "id": "001", "name": "node1-host", "ip": "127.0.0.1" },
  "data": { "srcip": "172.20.0.1" },
  "decoder": { "name": "web-accesslog" },
  "full_log": "172.20.0.1 - - [...] \"GET /rest/products/search?q=...UNION SELECT... HTTP/1.1\" 500"
}
```
→ `WazuhLog(rule_id=31103, rule_level=7, source_agent="node1-host",
source_ip="127.0.0.1", attacker_ip="172.20.0.1", decoder_name="web-accesslog", …)`.

## Custom rules

AEGIS ships custom Wazuh rules (IDs `100001`–`100042`) in
[`docker/node1/wazuh/config/local_rules.xml`](../docker/node1/wazuh/config/local_rules.xml),
documented in [runbooks/wazuh-rules.md](runbooks/wazuh-rules.md). They cover
identity/AD, ransomware, exfiltration, SOC-tampering and C2 scenarios that the generic
ruleset misses.
