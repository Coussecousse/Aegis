-- AEGIS PostgreSQL schema for asset profiles + UEBA time-series
-- Replaces ChromaDB with native auth, encryption at rest (LUKS), and TTL enforcement

-- Asset profiles: quasi-static metadata (identity, criticality, baselines)
CREATE TABLE IF NOT EXISTS asset_profiles (
    asset_id VARCHAR(255) PRIMARY KEY,
    asset_name VARCHAR(255) NOT NULL,
    asset_criticality VARCHAR(10) NOT NULL CHECK (asset_criticality IN ('tier0', 'tier1', 'tier2')),
    asset_description TEXT DEFAULT '',
    baseline_description TEXT NOT NULL DEFAULT 'No baseline',
    associated_users JSONB NOT NULL DEFAULT '[]'::jsonb,
    normal_activity_window VARCHAR(255) NOT NULL DEFAULT 'Unknown',
    recent_anomalies JSONB NOT NULL DEFAULT '[]'::jsonb,
    baseline_rate DOUBLE PRECISION NOT NULL DEFAULT 1.0,
    has_baseline BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_asset_profiles_criticality ON asset_profiles(asset_criticality);
CREATE INDEX idx_asset_profiles_updated_at ON asset_profiles(updated_at);
CREATE INDEX idx_asset_profiles_has_baseline ON asset_profiles(has_baseline);

-- UEBA activity: high-frequency time-series (one row per alert event)
-- Partitioned by month for efficient TTL purging (DROP old partitions)
CREATE TABLE IF NOT EXISTS ueba_activity (
    id BIGSERIAL,
    asset_id VARCHAR(255) NOT NULL REFERENCES asset_profiles(asset_id) ON DELETE CASCADE,
    event_timestamp DOUBLE PRECISION NOT NULL,  -- epoch seconds (compat with existing ueba.py)
    anomaly_score DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
) PARTITION BY RANGE (created_at);

-- Initial partition (current month) — cronjob creates future partitions
CREATE TABLE IF NOT EXISTS ueba_activity_default PARTITION OF ueba_activity DEFAULT;

CREATE INDEX idx_ueba_activity_asset_time ON ueba_activity(asset_id, event_timestamp DESC);
CREATE INDEX idx_ueba_activity_created_at ON ueba_activity(created_at);

-- Trigger to auto-update asset_profiles.updated_at on any change
CREATE OR REPLACE FUNCTION update_asset_timestamp()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_asset_profiles_updated_at
BEFORE UPDATE ON asset_profiles
FOR EACH ROW
EXECUTE FUNCTION update_asset_timestamp();

-- TTL cleanup function: purge ueba_activity > 2 years (called by cron or pg_cron)
-- Retention: 2 years for audit logs per CNIL requirements
CREATE OR REPLACE FUNCTION cleanup_expired_ueba_events()
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    cutoff TIMESTAMPTZ;
    result BIGINT;
BEGIN
    cutoff := NOW() - INTERVAL '2 years';
    DELETE FROM ueba_activity WHERE created_at < cutoff;
    GET DIAGNOSTICS result = ROW_COUNT;
    RETURN QUERY SELECT result;
END;
$$ LANGUAGE plpgsql;

-- TTL cleanup function: purge asset_profiles with no activity in 2 years
-- Inactive assets (no ueba_activity in 2 years) are candidates for deletion (GDPR minimization)
CREATE OR REPLACE FUNCTION cleanup_inactive_asset_profiles()
RETURNS TABLE(deleted_count BIGINT) AS $$
DECLARE
    cutoff TIMESTAMPTZ;
    result BIGINT;
BEGIN
    cutoff := NOW() - INTERVAL '2 years';
    DELETE FROM asset_profiles
    WHERE asset_id IN (
        SELECT ap.asset_id
        FROM asset_profiles ap
        LEFT JOIN ueba_activity ua ON ap.asset_id = ua.asset_id AND ua.created_at >= cutoff
        WHERE ua.asset_id IS NULL
    );
    GET DIAGNOSTICS result = ROW_COUNT;
    RETURN QUERY SELECT result;
END;
$$ LANGUAGE plpgsql;

-- Grant permissions to aegis application user (created in docker-entrypoint)
-- Least privilege: SELECT, INSERT, UPDATE, DELETE on tables only (no DDL)
GRANT SELECT, INSERT, UPDATE, DELETE ON asset_profiles TO aegis_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON ueba_activity TO aegis_app;
GRANT USAGE, SELECT ON SEQUENCE ueba_activity_id_seq TO aegis_app;
