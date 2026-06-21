#!/bin/sh
set -e

echo "$(date -Iseconds) [INFO] Starting RGPD TTL cleanup"

# Cleanup UEBA events > 2 years
UEBA_COUNT=$(PGPASSWORD="${POSTGRES_PASSWORD}" psql \
  -h aegis-node1-postgres-1 \
  -U "${POSTGRES_USER}" \
  -d "${POSTGRES_DB}" \
  -t -c "SELECT cleanup_expired_ueba_events();" | xargs)
echo "$(date -Iseconds) [INFO] Deleted ${UEBA_COUNT} expired UEBA events"

# Cleanup inactive asset profiles (no activity in 2 years)
PROFILE_COUNT=$(PGPASSWORD="${POSTGRES_PASSWORD}" psql \
  -h aegis-node1-postgres-1 \
  -U "${POSTGRES_USER}" \
  -d "${POSTGRES_DB}" \
  -t -c "SELECT cleanup_inactive_asset_profiles();" | xargs)
echo "$(date -Iseconds) [INFO] Deleted ${PROFILE_COUNT} inactive asset profiles"

echo "$(date -Iseconds) [INFO] RGPD TTL cleanup complete"
