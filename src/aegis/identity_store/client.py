"""Async ChromaDB client for AEGIS RAG asset enrichment."""

import asyncio
import importlib
import inspect
import json
import logging
import time
from typing import Any, Literal, cast

import httpx

from aegis.identity_store import ueba
from aegis.identity_store.base import BaseIdentityConnector
from aegis.middleware.models import RagContext, UEBAMetrics

logger = logging.getLogger(__name__)


def _get_chromadb_module() -> Any:
    """Load chromadb lazily to avoid import-time failures on unsupported platforms."""
    return importlib.import_module("chromadb")


class ChromaDBClient:
    """Client for ChromaDB metadata lookup by asset identifier."""

    def __init__(self, host: str = "localhost", port: int = 8000, timeout: float = 5.0) -> None:
        """Initialize ChromaDB async HTTP client configuration.

        Args:
            host: ChromaDB server host.
            port: ChromaDB server port.
            timeout: Request timeout in seconds.
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self._client: Any | None = None
        self._collection: Any | None = None
        self._collection_name = "aegis_assets"
        self._sync_mode = False
        logger.info(f"ChromaDB client initialized: {host}:{port}")

    async def __aenter__(self) -> "ChromaDBClient":
        """Create async ChromaDB client and ensure collection exists."""
        await self._ensure_collection()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close HTTP resources at context exit."""
        await self.close()

    async def _ensure_collection(self) -> Any:
        """Ensure `aegis_assets` collection exists and cache it."""
        if self._collection is not None:
            return self._collection
        if self._client is None:
            chromadb_module = _get_chromadb_module()
            async_http_client = getattr(chromadb_module, "AsyncHttpClient", None)
            if async_http_client is not None:
                self._client = await self._maybe_await(
                    async_http_client(
                        host=self.host,
                        port=self.port,
                    )
                )
            else:
                http_client = getattr(chromadb_module, "HttpClient", None)
                if http_client is None:
                    raise RuntimeError(
                        "chromadb client is unavailable "
                        "(neither AsyncHttpClient nor HttpClient found)"
                    )
                self._sync_mode = True
                self._client = http_client(
                    host=self.host,
                    port=self.port,
                )

        self._collection = await self._call(
            self._client.get_or_create_collection,
            name=self._collection_name,
        )
        return self._collection

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        """Retrieve enriched context for an asset using metadata lookup by `asset_id`.

        Args:
            asset_identifier: Asset identifier (hostname, id, or IP).

        Returns:
            RagContext: Enriched context, or tier2 fallback when unavailable.
        """
        try:
            collection = await self._ensure_collection()
            results = await self._call(collection.get, ids=[asset_identifier])
            metadatas = results.get("metadatas", []) if isinstance(results, dict) else []

            if not metadatas:
                logger.warning(
                    f"asset_id={asset_identifier!r} not found in ChromaDB, defaulting to tier2"
                )
                return self._create_default_context(asset_identifier)

            metadata = metadatas[0] if isinstance(metadatas, list) and metadatas else None
            if not isinstance(metadata, dict):
                logger.warning(
                    f"asset_id={asset_identifier!r} not found in ChromaDB, defaulting to tier2"
                )
                return self._create_default_context(asset_identifier)

            return self._context_from_metadata(asset_identifier, cast(dict[str, Any], metadata))

        except (httpx.TimeoutException, TimeoutError):
            logger.warning(
                f"asset_id={asset_identifier!r} not found in ChromaDB, defaulting to tier2"
            )
            return self._create_default_context(asset_identifier)
        except Exception:
            logger.exception("Unexpected ChromaDB error while fetching asset context")
            return self._create_default_context(asset_identifier)

    async def record_activity(self, asset_identifier: str, now: float | None = None) -> RagContext:
        """Record one activity event for an asset and recompute its behavioral score.

        Updates the trailing event window + EWMA baseline persisted in ChromaDB
        (Gap 2 behavioral UEBA) and returns the asset context with a fresh
        ``anomaly_score`` reflecting how far recent activity deviates from the
        asset's own baseline. For an **unprofiled** asset (not in ChromaDB) this
        is a no-op returning the tier2 default — behavioral baselines only apply
        to known assets; an unprofiled one still fails open in triage.

        Args:
            asset_identifier: Asset identifier (hostname, id, or IP).
            now: Event timestamp (epoch seconds); defaults to the current time.

        Returns:
            RagContext: Context with the recomputed behavioral anomaly score, or
            the tier2 fallback for an unknown/erroring asset.
        """
        ts_now = time.time() if now is None else now
        try:
            collection = await self._ensure_collection()
            results = await self._call(collection.get, ids=[asset_identifier])
            metadatas = results.get("metadatas", []) if isinstance(results, dict) else []
            metadata = metadatas[0] if isinstance(metadatas, list) and metadatas else None
            if not isinstance(metadata, dict):
                return self._create_default_context(asset_identifier)

            meta = dict(cast(dict[str, Any], metadata))
            window = ueba.prune_window(
                self._parse_float_list(meta.get("event_timestamps", "[]")), ts_now
            )
            window.append(ts_now)
            recent_count = len(window)
            baseline = float(meta.get("baseline_rate", 1.0) or 1.0)

            meta["anomaly_score"] = str(ueba.anomaly_score(recent_count, baseline))
            meta["baseline_rate"] = str(ueba.update_baseline(baseline, recent_count))
            meta["event_timestamps"] = json.dumps(window)

            await self._call(
                collection.upsert, ids=[asset_identifier], metadatas=[meta], embeddings=[[0.0]]
            )
            return self._context_from_metadata(asset_identifier, meta)
        except (httpx.TimeoutException, TimeoutError):
            return self._create_default_context(asset_identifier)
        except Exception:
            logger.exception("Failed to record activity for behavioral UEBA")
            return self._create_default_context(asset_identifier)

    def _context_from_metadata(self, asset_identifier: str, metadata: dict[str, Any]) -> RagContext:
        """Convert Chroma metadata into the local RagContext model."""
        raw_criticality = str(metadata.get("asset_criticality", "tier2"))
        if raw_criticality not in {"tier0", "tier1", "tier2"}:
            raw_criticality = "tier2"
        criticality: Literal["tier0", "tier1", "tier2"] = cast(
            Literal["tier0", "tier1", "tier2"], raw_criticality
        )

        similar_incidents_raw = metadata.get("similar_incidents", "[]")
        similar_incidents: list[str]
        if isinstance(similar_incidents_raw, str):
            try:
                parsed_incidents = json.loads(similar_incidents_raw)
                similar_incidents = [str(item) for item in parsed_incidents]
            except json.JSONDecodeError:
                similar_incidents = []
        elif isinstance(similar_incidents_raw, list):
            similar_incidents = [str(item) for item in similar_incidents_raw]
        else:
            similar_incidents = []

        return RagContext(
            asset_name=str(metadata.get("asset_name", asset_identifier)),
            asset_criticality=criticality,
            asset_description=str(metadata.get("asset_description", "")),
            similar_incidents=similar_incidents,
            ueba=self._extract_ueba(metadata),
        )

    def _extract_ueba(self, metadata: dict[str, Any]) -> UEBAMetrics:
        """Build UEBA metrics from metadata, with neutral defaults when unavailable."""
        associated_users_raw = metadata.get("associated_users", "[]")
        recent_anomalies_raw = metadata.get("recent_anomalies", "[]")

        associated_users = self._parse_string_list(associated_users_raw)
        recent_anomalies = self._parse_string_list(recent_anomalies_raw)
        anomaly_score_raw = metadata.get("anomaly_score", 0.0)
        baseline_description = str(metadata.get("baseline_description", "No baseline"))
        normal_activity_window = str(metadata.get("normal_activity_window", "Unknown"))
        has_baseline = True

        if (
            "baseline_description" not in metadata
            and "associated_users" not in metadata
            and "normal_activity_window" not in metadata
            and "recent_anomalies" not in metadata
            and "anomaly_score" not in metadata
        ):
            logger.info("UEBA metrics missing in ChromaDB entry; using neutral defaults")
            baseline_description = "No baseline"
            associated_users = []
            normal_activity_window = "Unknown"
            recent_anomalies = []
            anomaly_score_raw = 0.0
            has_baseline = False

        return UEBAMetrics(
            has_baseline=has_baseline,
            baseline_description=baseline_description,
            associated_users=associated_users,
            normal_activity_window=normal_activity_window,
            recent_anomalies=recent_anomalies,
            anomaly_score=float(anomaly_score_raw),
        )

    @staticmethod
    def _parse_float_list(value: Any) -> list[float]:
        """Parse a metadata list of floats from a JSON string or native list."""
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return []
        elif isinstance(value, list):
            parsed = value
        else:
            return []
        out: list[float] = []
        for item in parsed if isinstance(parsed, list) else []:
            try:
                out.append(float(item))
            except (TypeError, ValueError):
                continue
        return out

    @staticmethod
    def _parse_string_list(value: Any) -> list[str]:
        """Parse metadata list values from JSON strings or native list objects."""
        if isinstance(value, str):
            try:
                parsed = json.loads(value)
            except json.JSONDecodeError:
                return []
            if isinstance(parsed, list):
                return [str(item) for item in parsed]
            return []
        if isinstance(value, list):
            return [str(item) for item in value]
        return []

    @staticmethod
    def _create_default_context(asset_identifier: str) -> RagContext:
        """Create a tier2 fallback context for unknown assets."""
        return RagContext(
            asset_name=asset_identifier,
            asset_criticality="tier2",
            asset_description="Unknown asset - no metadata found in ChromaDB",
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

    async def index_asset(self, context: RagContext) -> bool:
        """Upsert an asset into ChromaDB metadata collection.

        Args:
            context: Rag context to persist.

        Returns:
            bool: True when request succeeds.
        """
        try:
            collection = await self._ensure_collection()
            metadata = {
                "asset_name": context.asset_name,
                "asset_criticality": context.asset_criticality,
                "asset_description": context.asset_description,
                "similar_incidents": json.dumps(context.similar_incidents),
                "baseline_description": context.ueba.baseline_description,
                "associated_users": json.dumps(context.ueba.associated_users),
                "normal_activity_window": context.ueba.normal_activity_window,
                "recent_anomalies": json.dumps(context.ueba.recent_anomalies),
                "anomaly_score": str(context.ueba.anomaly_score),
            }
            await self._call(
                collection.upsert,
                ids=[context.asset_name],
                metadatas=[metadata],
                embeddings=[[0.0]],
            )
            return True
        except Exception:
            logger.exception("Failed to index asset into ChromaDB")
            return False

    async def sync_asset_identity(self, asset_id: str, connector: BaseIdentityConnector) -> bool:
        """Synchronize identity context into ChromaDB via ETL.

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

        try:
            collection = await self._ensure_collection()
            metadata = {
                "asset_name": context.asset_name,
                "asset_criticality": context.asset_criticality,
                "asset_description": context.asset_description,
                "identity_asset_id": asset_id,
                "similar_incidents": json.dumps(context.similar_incidents),
                "baseline_description": context.ueba.baseline_description,
                "associated_users": json.dumps(context.ueba.associated_users),
                "normal_activity_window": context.ueba.normal_activity_window,
                "recent_anomalies": json.dumps(context.ueba.recent_anomalies),
                "anomaly_score": str(context.ueba.anomaly_score),
            }
            await self._call(
                collection.upsert,
                ids=[asset_id],
                metadatas=[metadata],
                embeddings=[[0.0]],
            )
            return True
        except Exception:
            logger.exception("Failed to sync identity context into ChromaDB")
            return False

    async def close(self) -> None:
        """Close ChromaDB async resources when supported by the client implementation."""
        if self._client is not None:
            close_method = getattr(self._client, "close", None)
            if callable(close_method):
                await self._call(close_method)
            self._client = None
            self._collection = None

    async def _call(self, fn: Any, /, **kwargs: Any) -> Any:
        """Call a ChromaDB method via asyncio.to_thread in sync mode, _maybe_await otherwise."""
        if self._sync_mode:
            return await asyncio.to_thread(fn, **kwargs)
        return await self._maybe_await(fn(**kwargs))

    @staticmethod
    async def _maybe_await(value: Any) -> Any:
        """Await the value when needed, otherwise return it unchanged."""
        if inspect.isawaitable(value):
            return await value
        return value
