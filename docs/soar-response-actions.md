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

## State (v0.6.0)

- ✅ **Policy config**: a human-maintained `rule_id → action` map with an `auto` flag,
  loaded from `RESPONSE_POLICY_FILE` ([`response_policy.py`](../src/aegis/soar/response_policy.py));
  empty by default (no automatic action). Example:
  [`response-policies.example.json`](../docker/node1/response-policies.example.json).
- ✅ **Pipeline**: when an alert's rule matches a policy, the report's `decision` gains an
  `applied_response` (`rule_id`, rendered `action`, `auto_applied`); an `auto` policy sets
  `auto_remediation_allowed = True` while `requires_human_validation` stays `True`.
- ✅ Report delivery to Shuffle; human-in-the-loop triage workflow template
  ([`aegis-triage-v1.json`](../docker/node1/shuffle/playbooks/aegis-triage-v1.json)).
- ⏳ **Remaining (Shuffle side):** the workflows that read `applied_response` and actually
  execute the containment (firewall block, account lock) + write the execution result back.

## Enable it

```bash
cp docker/node1/response-policies.example.json docker/node1/response-policies.json
# edit it: rule_id → action ({actor}/{host}/{url}), auto=true|false
echo 'RESPONSE_POLICY_FILE=/path/in/container/response-policies.json' >> .env
# mount the file into the middleware container, then recreate it
```

## Verify the rules in Shuffle

In the `AEGIS Alerts` workflow, branch on the report fields (the middleware already
fills them):

1. **Read** `decision.applied_response` from the incoming report.
2. **If `applied_response.auto_applied == true`** → run the containment action
   automatically (e.g. *Block IP* = `applied_response.action` target), then post the
   result back to the incident — the card states *"pre-approved action taken"*.
3. **If `applied_response` is set but `auto_applied == false`** → pre-stage the action on
   the card with a one-click *Approve* button (human confirms).
4. **If `applied_response` is null** → normal human-in-the-loop triage (validate
   `decision.recommended_action`).

To test end-to-end: add a policy for a rule you can trigger (e.g. SSH brute force
`5712`, `auto: true`), attack from Kali, and check the report carries
`applied_response.auto_applied = true` and your Shuffle workflow executed the block.
