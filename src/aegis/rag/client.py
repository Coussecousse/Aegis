"""Async ChromaDB client for AEGIS RAG asset enrichment."""

import json
import logging
from typing import Any, Literal, cast

import httpx

from aegis.middleware.models import RagContext, UEBAMetrics

logger = logging.getLogger(__name__)


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
        self.base_url = f"http://{host}:{port}"
        self._client: httpx.AsyncClient | None = None
        self._collection_name = "aegis_assets"
        self._collection_id: str | None = None
        logger.info(f"ChromaDB client initialized: {host}:{port}")

    async def __aenter__(self) -> "ChromaDBClient":
        """Create the underlying HTTP client and ensure collection exists."""
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)
        await self._ensure_collection()
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Close HTTP resources at context exit."""
        await self.close()

    async def _ensure_collection(self) -> str:
        """Ensure `aegis_assets` exists and cache its collection id."""
        if self._collection_id is not None:
            return self._collection_id
        if self._client is None:
            self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

        response = await self._client.post(
            "/api/v1/collections",
            json={"name": self._collection_name, "get_or_create": True},
        )
        response.raise_for_status()
        payload = response.json()
        if not isinstance(payload, dict) or "id" not in payload:
            raise ValueError("Invalid ChromaDB collection response")
        self._collection_id = str(payload["id"])
        return self._collection_id

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        """Retrieve enriched context for an asset using metadata lookup by `asset_id`.

        Args:
            asset_identifier: Asset identifier (hostname, id, or IP).

        Returns:
            RagContext: Enriched context, or tier2 fallback when unavailable.
        """
        try:
            collection_id = await self._ensure_collection()
            if self._client is None:
                self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

            response = await self._client.post(
                f"/api/v1/collections/{collection_id}/get",
                json={
                    "where": {"asset_id": asset_identifier},
                    "limit": 1,
                    "include": ["metadatas"],
                },
            )
            response.raise_for_status()
            payload = response.json()
            metadatas = payload.get("metadatas", []) if isinstance(payload, dict) else []

            if not metadatas:
                logger.warning(
                    f"asset_id={asset_identifier} not found in ChromaDB, defaulting to tier2"
                )
                return self._create_default_context(asset_identifier)

            first_metadata = metadatas[0] if isinstance(metadatas, list) and metadatas else None
            metadata = (
                first_metadata[0] if isinstance(first_metadata, list) and first_metadata else None
            )
            if not isinstance(metadata, dict):
                logger.warning(
                    f"asset_id={asset_identifier} not found in ChromaDB, defaulting to tier2"
                )
                return self._create_default_context(asset_identifier)

            return self._context_from_metadata(asset_identifier, cast(dict[str, Any], metadata))

        except (httpx.TimeoutException, TimeoutError):
            logger.warning(
                f"asset_id={asset_identifier} not found in ChromaDB, defaulting to tier2"
            )
            return self._create_default_context(asset_identifier)
        except Exception:
            logger.exception("Unexpected ChromaDB error while fetching asset context")
            return self._create_default_context(asset_identifier)

    def _context_from_metadata(self, asset_identifier: str, metadata: dict[str, Any]) -> RagContext:
        """Convert Chroma metadata into the local RagContext model."""
        raw_criticality = str(metadata.get("criticality_tier", "tier2"))
        if raw_criticality not in {"tier0", "tier1", "tier2"}:
            raw_criticality = "tier2"
        criticality: Literal["tier0", "tier1", "tier2"] = cast(
            Literal["tier0", "tier1", "tier2"], raw_criticality
        )

        ueba = self._extract_ueba(metadata)
        similar_incidents = metadata.get("similar_incidents", [])
        if not isinstance(similar_incidents, list):
            similar_incidents = []

        return RagContext(
            asset_name=str(metadata.get("asset_name", asset_identifier)),
            asset_criticality=criticality,
            asset_description=str(
                metadata.get("asset_description", "Unknown asset - no metadata found in ChromaDB")
            ),
            similar_incidents=[str(item) for item in similar_incidents],
            ueba=ueba,
        )

    def _extract_ueba(self, metadata: dict[str, Any]) -> UEBAMetrics:
        """Build UEBA metrics from metadata, with neutral defaults when unavailable."""
        raw_ueba = metadata.get("ueba")
        if isinstance(raw_ueba, str):
            try:
                raw_ueba = json.loads(raw_ueba)
            except json.JSONDecodeError:
                raw_ueba = None

        if not isinstance(raw_ueba, dict):
            logger.info("UEBA metrics missing in ChromaDB entry; using neutral defaults")
            return UEBAMetrics(
                baseline_description="No historical baseline available. Asset is new or untracked.",
                associated_users=[],
                normal_activity_window="Unknown",
                recent_anomalies=[],
                anomaly_score=0.0,
            )

        associated_users = raw_ueba.get("associated_users", [])
        recent_anomalies = raw_ueba.get("recent_anomalies", [])
        anomaly_score = raw_ueba.get("anomaly_score", 0.0)
        if not isinstance(associated_users, list):
            associated_users = []
        if not isinstance(recent_anomalies, list):
            recent_anomalies = []

        return UEBAMetrics(
            baseline_description=str(
                raw_ueba.get(
                    "baseline_description",
                    "No historical baseline available. Asset is new or untracked.",
                )
            ),
            associated_users=[str(item) for item in associated_users],
            normal_activity_window=str(raw_ueba.get("normal_activity_window", "Unknown")),
            recent_anomalies=[str(item) for item in recent_anomalies],
            anomaly_score=float(anomaly_score),
        )

    @staticmethod
    def _create_default_context(asset_identifier: str) -> RagContext:
        """Create a tier2 fallback context for unknown assets."""
        return RagContext(
            asset_name=asset_identifier,
            asset_criticality="tier2",
            asset_description="Unknown asset - no metadata found in ChromaDB",
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description="No historical baseline available. Asset is new or untracked.",
                associated_users=[],
                normal_activity_window="Unknown",
                recent_anomalies=[],
                anomaly_score=0.0,
            ),
        )

    async def get_asset_context_by_ip(self, ip_address: str) -> RagContext:
        """Retrieve asset context by IP address."""
        return await self.get_asset_context(ip_address)

    async def get_asset_context_by_name(self, asset_name: str) -> RagContext:
        """Retrieve asset context by asset name."""
        return await self.get_asset_context(asset_name)

    async def index_asset(self, context: RagContext) -> bool:
        """Upsert an asset into ChromaDB metadata collection.

        Args:
            context: Rag context to persist.

        Returns:
            bool: True when request succeeds.
        """
        try:
            collection_id = await self._ensure_collection()
            if self._client is None:
                self._client = httpx.AsyncClient(base_url=self.base_url, timeout=self.timeout)

            payload = {
                "ids": [context.asset_name],
                "metadatas": [
                    {
                        "asset_id": context.asset_name,
                        "asset_name": context.asset_name,
                        "criticality_tier": context.asset_criticality,
                        "asset_description": context.asset_description,
                        "similar_incidents": context.similar_incidents,
                        "ueba": context.ueba.model_dump(),
                    }
                ],
                "documents": [context.asset_description],
            }
            response = await self._client.post(
                f"/api/v1/collections/{collection_id}/upsert",
                json=payload,
            )
            response.raise_for_status()
            return True
        except Exception:
            logger.exception("Failed to index asset into ChromaDB")
            return False

    async def get_similar_incidents(self, asset_name: str, limit: int = 5) -> list[dict[str, Any]]:
        """Return similar incidents for an asset.

        This minimal implementation keeps backward compatibility for callers.

        Args:
            asset_name: Asset name to query.
            limit: Maximum incident count.

        Returns:
            list[dict[str, Any]]: Incident summaries.
        """
        _ = asset_name
        _ = limit
        return []

    async def close(self) -> None:
        """Close ChromaDB HTTP resources."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None
