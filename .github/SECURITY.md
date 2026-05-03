# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in AEGIS, do **not** open a public GitHub issue.

Use private disclosure only:

- Send an encrypted email to: **adob.e@hotmail.com**
- If you cannot encrypt your first message, send a minimal contact request and we will provide a
  secure channel for full details

Please include the following information:

1. A clear description of the vulnerability
2. Reproduction steps (proof-of-concept if available)
3. Potential impact and affected components

## Response Commitments

- We will acknowledge receipt within **48 hours**
- We will provide a remediation plan and timeline within **90 days**

If additional coordination is needed (for example, coordinated disclosure with downstream users),
we will communicate proposed dates explicitly.

## Scope and Severity Notes

AEGIS is a sovereign on-premise SOC orchestrator. Any finding that could enable data exfiltration,
external data leakage, or unauthorized outbound communication is treated as **high priority**,
as it may violate the project sovereignty rules (no external data transfer).

## Supported Versions

At this early stage, only the latest version on the default branch is actively supported for
security fixes.
