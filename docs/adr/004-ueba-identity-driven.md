# ADR 004: UEBA driven by the identity store

- Status: Accepted
- Date: 2026-06-15

## Context

AEGIS enriches alerts with per-asset UEBA context (criticality tier, baseline,
anomaly score) read from ChromaDB. The identity connector that fills that context
from an external store was pluggable and implemented for LDAP/AD
(`BaseIdentityConnector`, `LdapConnector`, `ChromaDBClient.sync_asset_identity`,
the `identity.sync` consumer), **but nothing ever enqueued sync jobs** — so in
practice the UEBA context for a freshly-seen asset never updated. The goal: using
any identity store (LDAP here, Active Directory tomorrow) should keep the UEBA
up to date automatically.

## Decision

**Event-driven sync trigger.** During triage, when an alert concerns an
**unprofiled asset** (`rag.ueba.has_baseline` is False), `triage_log` invokes an
`on_unprofiled_asset(asset_id)` callback. The triage consumer wires a callback
that publishes an `{asset_id}` job to the `identity.sync` routing key (already
bound to the `identity.sync` queue). The `identity.sync` consumer then runs
`sync_asset_identity`, pulling the asset's context from the identity store into
ChromaDB.

- **Self-limiting**: once synced, `has_baseline` flips True, so triage stops
  asking for that asset.
- **TTL dedup** (`TriageProcessor._should_request_sync`): a burst on the same
  unprofiled asset enqueues a single sync while the first is in flight.
- **Non-blocking**: a publish failure is swallowed and never drops the alert.
- **Store-agnostic**: swapping LDAP for Active Directory/Okta is a new
  `BaseIdentityConnector` adapter; the trigger and the rest are unchanged.

Behavioral scoring (a dynamic `anomaly_score` from observed activity, replacing
the current identity-derived heuristic) is a **separate follow-up** (UEBA Gap 2),
not part of this ADR.

## Consequences (positive)

- The UEBA context self-populates the first time an asset is seen; subsequent
  alerts for it use the real tier/baseline at triage and scoring.
- The objective "any identity DB keeps UEBA updated" is met for the wiring; only
  the connector adapter changes per store.

## Consequences (negative)

- A failed identity lookup writes a **default tier2 profile** (with
  `has_baseline` True), which then re-enables the false-positive gate for that
  asset. Acceptable for now; to be refined alongside Gap 2 behavioral scoring.
- `anomaly_score` stays identity-derived (privilege-based) until Gap 2.
- The dedup is in-process (per triage consumer); a restart re-allows one sync per
  asset — harmless given sync idempotence.
