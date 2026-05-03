# ADR 001: Version custom Wazuh rules in Git

- Status: Accepted
- Date: 2026-05-03

## Context

AEGIS needs custom Wazuh detection rules that are reproducible, auditable, and deployable through CI workflows. Configuring rules directly in the Wazuh Dashboard UI introduces drift risk between environments and weakens traceability of security changes.

## Decision

All custom Wazuh rules must live in `docker/node1/wazuh/config/local_rules.xml` and be versioned in Git. Rule changes are made through pull requests, reviewed, and deployed by restarting the Wazuh Manager container.

## Consequences (positive)

- Rules are code-reviewed before production use.
- Every change is tracked in Git history (who, what, when, why).
- Deployments are deterministic across environments.
- Rules are loaded automatically on container restart; no manual dashboard configuration is required.

## Consequences (negative)

- Applying rule changes requires a Wazuh Manager container restart.
- This adds a short operational step to deployments, but restart time is acceptable (<30s).
