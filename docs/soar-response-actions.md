# AEGIS — SOAR Response Actions

How a detected threat becomes a **contained** one, and how AEGIS reports whether an
action was taken. This is the *response* layer (Shuffle SOAR), separate from how the
report is written.

> **Two different things, don't confuse them:**
> - **Recommendation (middleware):** the local LLM *writes* `recommended_action` in
>   plain language (attacker IP + endpoint). There is **no deterministic playbook** in
>   the middleware — the model reasons about the recommendation.
> - **Response policy (this doc):** a **human pre-defines**, once, what to do for a
>   given Wazuh rule code (e.g. "rule = SSH brute force → block the source IP"). When
>   that code fires, the response is applied per the human's standing decision, and
>   AEGIS **records and reports whether the action was taken** — tied to the rule code,
>   not to the LLM's opinion.

## The model

A response policy maps a **Wazuh `rule_id`** (or rule family) to a **predefined
action** with a target taken from the alert (IP / host / account). The human owns this
mapping; it is their pre-approval. Example:

| Wazuh rule | Pre-defined action | Target |
|---|---|---|
| 5710 / 5712 (SSH brute force) | Block the source IP at the firewall | `attacker_ip` |
| 31103 / 31164 (SQL injection) | Block the source IP; flag the endpoint | `attacker_ip`, endpoint |
| 100011 (ransomware) | Isolate the host | `source_agent` |

## Human-in-the-loop — two modes

Per-incident validation stays the default (the non-negotiable rule). A pre-defined
policy is **pre-approval**: the human decided in advance, so the action may apply
without a per-incident click.

| `decision` fields | Meaning |
|---|---|
| `requires_human_validation = True`, `auto_remediation_allowed = False` | default — wait for a human (no policy for this rule) |
| `auto_remediation_allowed = True` | a human **pre-approved** a policy for this rule code → response applied automatically |
| `recommended_action` | the LLM's plain-language recommendation (always present) |

> ⚠️ **Decision to record:** enabling `auto_remediation_allowed = True` for some rule
> codes relaxes the strict "every critical action waits for explicit per-incident
> validation" rule (CLAUDE.md). It is a deliberate **pre-approval** policy, not silent
> auto-remediation. Keep it opt-in, per rule, reversible, and audited.

## Flow

```
Wazuh alert (rule_id) ─> pipeline ─> response policy for rule_id?
   ├─ yes (pre-approved): apply via Shuffle, mark action_taken in the report
   └─ no: requires_human_validation=True, operator validates in Shuffle
AegisReport ──(webhook)──> Shuffle ──> incident card (+ action status)
```

The middleware POSTs the full `AegisReport` ([`soar/client.py`](../src/aegis/soar/client.py))
to `SHUFFLE_WEBHOOK_URL`. It carries the structured fields a response needs:
`attack_type`, `decision.severity`, `decision.recommended_action`, `attacker_ip`/endpoint.

## Current state vs planned

- ✅ Report delivery to Shuffle; human-in-the-loop triage workflow template
  ([`aegis-triage-v1.json`](../docker/node1/shuffle/playbooks/aegis-triage-v1.json)).
- ✅ `decision.auto_remediation_allowed` / `requires_human_validation` exist in the model
  (today `auto_remediation_allowed` is always `False`).
- ⏳ **Not yet implemented:** the `rule_id → predefined action` policy config, the
  logic that sets `auto_remediation_allowed` from it, a report field recording the
  **action-taken status**, and the matching Shuffle workflows.

**To implement** (proposed): a small human-maintained map (`rule_id → action`,
`auto_remediation` flag), evaluated in the decision step; add an `applied_response`
(action + status) field to the report so the card and the narrative both state, as a
fact, that a pre-defined human action was taken for this rule code.
