# AEGIS — GDPR Article 30 Processing Register

**Controller:** [Organization]
**DPO:** [Name / Contact]

## 1. Purpose
Cybersecurity threat detection (GDPR Article 6(1)(f) — legitimate interest under NIS 2).

## 2. Data Categories
| Category | Examples | Storage |
|----------|----------|---------|
| Identity | Username, employee ID, group membership | PostgreSQL asset_profiles (encrypted at rest) |
| Behavioral | Event timestamps, anomaly scores | PostgreSQL ueba_activity (encrypted at rest) |
| Asset metadata | Hostname, IP, criticality tier | PostgreSQL asset_profiles |

**No special categories** (Article 9).

## 3. Recipients
SOC operators + incident response teams only. **No external sharing.**

## 4. Transfers
**None.** 100% on-premise, no cloud.

## 5. Retention
| Category | Retention | Automation |
|---|---|---|
| **UEBA events** | 2 years (CNIL audit log requirement) | Daily cleanup at 03:00 UTC via `postgres-cron` container (`cleanup_expired_ueba_events()`) |
| **Asset profiles** | Deleted after 2 years of inactivity | Daily cleanup at 03:00 UTC via `postgres-cron` container (`cleanup_inactive_asset_profiles()`) |
| **Alert logs (Wazuh)** | 7 days (defined in `ossec.conf`) | Wazuh internal rotation |
| **Middleware audit logs** | 2 years (CNIL audit log requirement) | Manual review and deletion |

## 6. Legal Basis
Article 6(1)(f) — legitimate interest (NIS 2 cybersecurity obligation).

## 7. Technical Measures
- **Encryption:** LUKS AES-256 for Postgres volume.
- **Access control:** Postgres user `aegis_app` with least privilege (no DDL).
- **Minimization:** Only aggregated UEBA metrics, no raw logs in Postgres.
- **Audit:** Prometheus metrics track all queries.

## 8. Data Subject Rights
Employees can exercise rights (access, rectification, erasure) via DPO. Right to object may be overridden if organization demonstrates compelling grounds (NIS 2 compliance).

## 9. Supervisory Authority
[National DPA — e.g., CNIL (France), BfDI (Germany)]

**Next review:** [Annual, or on schema change]
