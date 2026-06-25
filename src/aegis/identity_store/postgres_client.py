"""Async PostgreSQL client for AEGIS asset profiles + UEBA time-series.

Replaces ChromaDB with native auth, encryption at rest (LUKS), TTL enforcement.
Implements the same interface as ChromaDBClient for drop-in compatibility.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Literal, cast

import asyncpg

from aegis.identity_store import ueba
from aegis.identity_store.base import BaseIdentityConnector
from aegis.middleware.models import RagContext, UEBAMetrics

logger = logging.getLogger(__name__)


class PostgresIdentityStore:
    """PostgreSQL client for asset profiles + UEBA, same interface as ChromaDBClient."""

    def __init__(
        self,
        host: str = "localhost",
        port: int = 5432,
        database: str = "aegis",
        user: str = "aegis_app",
        password: str = "",
        timeout: float = 5.0,
    ) -> None:
        """Initialize PostgreSQL connection parameters.

        Args:
            host: Postgres server host.
            port: Postgres server port.
            database: Database name.
            user: Application user (least privilege).
            password: User password.
            timeout: Query timeout in seconds.
        """
        self.host = host
        self.port = port
        self.database = database
        self.user = user
        self.password = password
        self.timeout = timeout
        self._pool: asyncpg.Pool | None = None
        logger.info(f"PostgreSQL client initialized: {host}:{port}/{database} (user={user})")

    async def __aenter__(self) -> PostgresIdentityStore:
        """Create connection pool."""
        self._pool = await asyncpg.create_pool(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password,
            command_timeout=self.timeout,
            min_size=2,
            max_size=10,
        )
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close connection pool."""
        await self.close()

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        """Retrieve enriched context for an asset from asset_profiles + ueba_activity.

        Args:
            asset_identifier: Asset identifier (hostname, id, or IP).

        Returns:
            RagContext: Enriched context, or tier2 fallback when unavailable.
        """
        if self._pool is None:
            raise RuntimeError("PostgresIdentityStore used outside context manager")

        try:
            async with self._pool.acquire() as conn:
                row = await conn.fetchrow(
                    """
                    SELECT asset_name, asset_criticality, asset_description,
                           baseline_description, associated_users, normal_activity_window,
                           recent_anomalies, baseline_rate, has_baseline
                    FROM asset_profiles
                    WHERE asset_id = $1
                    """,
                    asset_identifier,
                )

            if not row:
                logger.warning(
                    f"asset_id={asset_identifier!r} not found in Postgres, defaulting to tier2"
                )
                return self._create_default_context(asset_identifier)

            # Compute current anomaly_score from recent event window
            anomaly_score = await self._compute_anomaly_score(
                asset_identifier, row["baseline_rate"]
            )

            associated_users_raw = row["associated_users"]
            recent_anomalies_raw = row["recent_anomalies"]
            associated_users = (
                json.loads(associated_users_raw)
                if isinstance(associated_users_raw, str)
                else associated_users_raw or []
            )
            recent_anomalies = (
                json.loads(recent_anomalies_raw)
                if isinstance(recent_anomalies_raw, str)
                else recent_anomalies_raw or []
            )

            return RagContext(
                asset_name=row["asset_name"],
                asset_criticality=cast(
                    Literal["tier0", "tier1", "tier2"], row["asset_criticality"]
                ),
                asset_description=row["asset_description"] or "",
                similar_incidents=[],
                ueba=UEBAMetrics(
                    has_baseline=row["has_baseline"],
                    baseline_description=row["baseline_description"],
                    associated_users=associated_users,
                    normal_activity_window=row["normal_activity_window"],
                    recent_anomalies=recent_anomalies,
                    anomaly_score=anomaly_score,
                ),
            )

        except (asyncpg.PostgresError, OSError):
            logger.warning(
                f"asset_id={asset_identifier!r} Postgres error, defaulting to tier2",
                exc_info=True,
            )
            return self._create_default_context(asset_identifier)

    async def record_activity(self, asset_identifier: str, now: float | None = None) -> RagContext:
        """Record one activity event and recompute behavioral score.

        Updates trailing event window + EWMA baseline in asset_profiles, inserts
        event into ueba_activity time-series.

        Args:
            asset_identifier: Asset identifier.
            now: Event timestamp (epoch seconds); defaults to current time.

        Returns:
            RagContext: Context with recomputed anomaly score, or tier2 fallback.
        """
        if self._pool is None:
            raise RuntimeError("PostgresIdentityStore used outside context manager")

        ts_now = time.time() if now is None else now

        try:
            async with self._pool.acquire() as conn:
                # Fetch current profile
                row = await conn.fetchrow(
                    """
                    SELECT baseline_rate, has_baseline
                    FROM asset_profiles
                    WHERE asset_id = $1
                    """,
                    asset_identifier,
                )

                if not row:
                    # Unprofiled asset → no-op (triage calls on_unprofiled_asset to sync)
                    return self._create_default_context(asset_identifier)

                baseline = row["baseline_rate"]

                # Fetch recent event window (last 5 min) from ueba_activity
                window_start = ts_now - 300.0  # 5 min window (ueba.WINDOW_SECONDS)
                timestamps = await conn.fetch(
                    """
                    SELECT event_timestamp
                    FROM ueba_activity
                    WHERE asset_id = $1 AND event_timestamp >= $2
                    ORDER BY event_timestamp ASC
                    """,
                    asset_identifier,
                    window_start,
                )

                window = [float(r["event_timestamp"]) for r in timestamps]
                window.append(ts_now)
                recent_count = len(window)

                # Recompute anomaly + baseline
                anomaly_score_val = ueba.anomaly_score(recent_count, baseline)
                new_baseline = ueba.update_baseline(baseline, recent_count)

                # Update asset_profiles baseline
                await conn.execute(
                    """
                    UPDATE asset_profiles
                    SET baseline_rate = $1, has_baseline = TRUE
                    WHERE asset_id = $2
                    """,
                    new_baseline,
                    asset_identifier,
                )

                # Insert event into ueba_activity
                await conn.execute(
                    """
                    INSERT INTO ueba_activity (asset_id, event_timestamp, anomaly_score)
                    VALUES ($1, $2, $3)
                    """,
                    asset_identifier,
                    ts_now,
                    anomaly_score_val,
                )

            # Return updated context
            return await self.get_asset_context(asset_identifier)

        except (asyncpg.PostgresError, OSError):
            logger.exception("Failed to record activity for behavioral UEBA")
            return self._create_default_context(asset_identifier)

    async def index_asset(self, context: RagContext) -> bool:
        """Upsert an asset into asset_profiles.

        Args:
            context: Rag context to persist.

        Returns:
            bool: True when request succeeds.
        """
        if self._pool is None:
            raise RuntimeError("PostgresIdentityStore used outside context manager")

        try:
            async with self._pool.acquire() as conn:
                await conn.execute(
                    """
                    INSERT INTO asset_profiles (
                        asset_id, asset_name, asset_criticality, asset_description,
                        baseline_description, associated_users, normal_activity_window,
                        recent_anomalies, baseline_rate, has_baseline
                    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                    ON CONFLICT (asset_id) DO UPDATE SET
                        asset_name = EXCLUDED.asset_name,
                        asset_criticality = EXCLUDED.asset_criticality,
                        asset_description = EXCLUDED.asset_description,
                        baseline_description = EXCLUDED.baseline_description,
                        associated_users = EXCLUDED.associated_users,
                        normal_activity_window = EXCLUDED.normal_activity_window,
                        recent_anomalies = EXCLUDED.recent_anomalies,
                        baseline_rate = EXCLUDED.baseline_rate,
                        has_baseline = EXCLUDED.has_baseline
                    """,
                    context.asset_name,
                    context.asset_name,
                    context.asset_criticality,
                    context.asset_description,
                    context.ueba.baseline_description,
                    json.dumps(context.ueba.associated_users),
                    context.ueba.normal_activity_window,
                    json.dumps(context.ueba.recent_anomalies),
                    0.0,  # baseline_rate starts at 0 until first activity
                    context.ueba.has_baseline,
                )
            return True

        except (asyncpg.PostgresError, OSError):
            logger.exception("Failed to index asset into Postgres")
            return False

    async def sync_asset_identity(self, asset_id: str, connector: BaseIdentityConnector) -> bool:
        """Synchronize identity context into Postgres via ETL.

        Args:
            asset_id: Identifier of the target asset.
            connector: Identity connector implementation used for extraction.

        Returns:
            bool: True when synchronization succeeds.
        """
        try:
            context = await connector.fetch_identity_context(asset_id)
        except ConnectionError:
            logger.warning(f"Failed to sync asset {asset_id}, fallback data applied")
            context = self._create_default_context(asset_id)
        except Exception:
            logger.exception("Unexpected identity connector failure during sync")
            context = self._create_default_context(asset_id)

        return await self.index_asset(context)

    async def close(self) -> None:
        """Close PostgreSQL connection pool."""
        if self._pool is not None:
            await self._pool.close()
            self._pool = None

    async def _compute_anomaly_score(self, asset_id: str, baseline: float) -> float:
        """Compute current anomaly_score from recent ueba_activity window."""
        if self._pool is None:
            return 0.0

        try:
            now = time.time()
            window_start = now - 300.0  # 5 min window
            async with self._pool.acquire() as conn:
                count = await conn.fetchval(
                    """
                    SELECT COUNT(*)
                    FROM ueba_activity
                    WHERE asset_id = $1 AND event_timestamp >= $2
                    """,
                    asset_id,
                    window_start,
                )
            return ueba.anomaly_score(count, baseline)
        except (asyncpg.PostgresError, OSError):
            return 0.0

    @staticmethod
    def _create_default_context(asset_identifier: str) -> RagContext:
        """Create a tier2 fallback context for unknown assets."""
        return RagContext(
            asset_name=asset_identifier,
            asset_criticality="tier2",
            asset_description="Unknown asset - no metadata found in Postgres",
            similar_incidents=[],
            ueba=UEBAMetrics(
                has_baseline=False,
                baseline_description="No baseline",
                associated_users=[],
                normal_activity_window="Unknown",
                recent_anomalies=[],
                anomaly_score=0.0,
            ),
        )
