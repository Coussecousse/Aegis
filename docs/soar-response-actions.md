# AEGIS — SOAR Response Actions (human-in-the-loop)

How a validated incident becomes a **contained** one. This is the *execution* layer
(Shuffle SOAR), separate from how the report is written.

> **Two different things, don't confuse them:**
> - **Recommendation (middleware):** the local LLM *writes* `recommended_action` in
>   plain language, naming the attacker IP + endpoint. There is **no deterministic
>   playbook** in the middleware — the model reasons about the action.
> - **Response (this doc, Shuffle):** predefined containment **workflows** that an
>   operator triggers *after approval*. These are templates by design — a firewall
>   block must be exact and auditable, not improvised.

The golden rule is unchanged: **nothing is executed without explicit human
validation** (`auto_remediation_allowed = False`).

## Flow

```
AegisReport ──(webhook)──> Shuffle ──> operator reviews ──> APPROVE ──> response workflow runs
   (severity,                (incident                         │ REJECT ──> archive, no action
    attacker_ip,              card)                            │
    recommended_action,                                        └─ predefined containment for
    attack_type)                                                  this attack type executes
```

The middleware POSTs the full `AegisReport`
([`soar/client.py`](../src/aegis/soar/client.py)) to `SHUFFLE_WEBHOOK_URL` (3 retries,
exponential backoff). The report carries everything a response needs: `attack_type`,
`decision.severity`, `decision.recommended_action`, and the `attacker_ip`/endpoint.

## Current state

- ✅ **Report delivery** to Shuffle (webhook, retry).
- ✅ **Human-in-the-loop triage workflow** template:
  [`docker/node1/shuffle/playbooks/aegis-triage-v1.json`](../docker/node1/shuffle/playbooks/aegis-triage-v1.json)
  — receives the report and presents it for validation.
- ✅ The report contains a specific, machine-parseable target (attacker IP + endpoint).

## Planned — predefined containment per attack type

The goal: each report's `attack_type` (or rule family) maps to a **predefined
containment workflow**, pre-staged on the incident card so the operator approves with
one click instead of crafting the response by hand.

| Attack family | Predefined containment (proposed) | Target field |
|---|---|---|
| SQL injection / XSS / traversal / web attack | Block `attacker_ip` at the firewall; flag the endpoint | `attacker_ip`, endpoint |
| SSH / AD brute force | Block source IP; lock/observe the targeted account | `attacker_ip`, account |
| Tier0 / privilege escalation | Isolate host; revoke session; urgent IAM review | `source_agent` |
| Ransomware / exfiltration | Isolate host; cut the outbound flow | `source_agent` |
| C2 / beaconing | Block the destination; quarantine the process | `attacker_ip` |

**Design constraints:**
- The mapping lives in **Shuffle** (the SOAR layer), not in the middleware — so
  response procedures evolve without touching the AI pipeline.
- Each workflow is **idempotent** and **reversible**, with the exact target taken from
  the report (no free-text execution).
- Trigger is **always** an explicit human approval; AEGIS only *pre-selects* the
  matching containment, it never fires it.
- Every executed action is logged back as an audit trail on the incident.

> Status: **not yet implemented** — this documents the intended design. The middleware
> already supplies the structured fields these workflows need.
