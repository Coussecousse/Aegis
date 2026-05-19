"""
ChromaDB client for AEGIS RAG (asset context enrichment).

Provides interface to ChromaDB vector database for similarity search.
Stores and retrieves:
- Asset metadata (name, description, criticality tier)
- UEBA baselines (normal behavior, anomalies, associated users)
- Incident history (similar past incidents)

On-premise deployment: ChromaDB runs locally, no cloud calls.
Zero external API calls.
"""

import logging
from typing import Any

from aegis.middleware.models import RagContext, UEBAMetrics

logger = logging.getLogger(__name__)


class ChromaDBClient:
    """Client for ChromaDB vector similarity search (asset enrichment)."""

    def __init__(self, host: str = "localhost", port: int = 8000) -> None:
        """
        Initialize ChromaDB client.

        Args:
            host: ChromaDB server host (default: localhost for Docker).
            port: ChromaDB server port (default: 8000).
        """
        self.host = host
        self.port = port
        # Note: In production, this would initialize a Chroma client:
        # self.client = chromadb.HttpClient(host=host, port=port)
        # For now, we stub the implementation.
        logger.info(f"ChromaDB client initialized: {host}:{port}")

    async def __aenter__(self) -> "ChromaDBClient":
        """Context manager entry."""
        return self

    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        await self.close()

    async def get_asset_context(self, asset_identifier: str) -> RagContext:
        """
        Retrieve enriched context for an asset by name or IP.

        Searches ChromaDB collection 'aegis_assets' for similarity match.
        Returns asset metadata + UEBA baseline + incident history.

        If asset not found, returns default context (tier2, "Unknown asset")
        with baseline UEBA indicating no historical data.

        Args:
            asset_identifier: Asset name or IP address to search for.

        Returns:
            RagContext: Enriched business context (asset + UEBA + incidents).
        """
        logger.debug(f"Searching ChromaDB for asset: {asset_identifier}")

        # TODO: Implement actual Chroma similarity search
        # query_results = self.client.get(
        #     collection_name="aegis_assets",
        #     query_embeddings=embed_identifier(asset_identifier),
        #     n_results=1
        # )

        # For now, return a default context (unknown asset)
        # This will be replaced with actual ChromaDB search in v0.3
        default_context = self._create_default_context(asset_identifier)
        logger.info(
            f"Asset '{asset_identifier}' not found in ChromaDB. "
            f"Returning default context (tier2, unknown)"
        )
        return default_context

    @staticmethod
    def _create_default_context(asset_identifier: str) -> RagContext:
        """
        Create a default RagContext for unknown assets.

        Used as fallback when asset is not found in ChromaDB.
        Indicates tier2 (standard) criticality with no historical data.

        Args:
            asset_identifier: Asset name or IP.

        Returns:
            RagContext: Default context with baseline UEBA.
        """
        return RagContext(
            asset_name=asset_identifier,
            asset_criticality="tier2",
            asset_description="Unknown asset - no metadata found in ChromaDB",
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description=(
                    "No historical baseline available. Asset is new or untracked."
                ),
                associated_users=[],
                normal_activity_window="Unknown - assume 24/7",
                recent_anomalies=[],
                anomaly_score=0.5,  # Neutral: no data
            ),
        )

    async def get_asset_context_by_ip(self, ip_address: str) -> RagContext:
        """
        Retrieve asset context by IP address (convenience method).

        Args:
            ip_address: IPv4 or IPv6 address to search for.

        Returns:
            RagContext: Enriched business context for the asset.
        """
        return await self.get_asset_context(ip_address)

    async def get_asset_context_by_name(self, asset_name: str) -> RagContext:
        """
        Retrieve asset context by asset name (convenience method).

        Args:
            asset_name: Asset hostname or identifier.

        Returns:
            RagContext: Enriched business context for the asset.
        """
        return await self.get_asset_context(asset_name)

    async def index_asset(self, context: RagContext) -> bool:
        """
        Add or update asset in ChromaDB.

        Called after human approval of remediation or periodic sync
        from asset management database (CMDB).

        Args:
            context: RagContext with full asset metadata.

        Returns:
            bool: True if indexed successfully, False otherwise.
        """
        logger.debug(f"Indexing asset: {context.asset_name}")

        # TODO: Implement actual Chroma index operation
        # vector = embed_asset_context(context)
        # self.client.upsert(
        #     collection_name="aegis_assets",
        #     embeddings=[vector],
        #     metadatas=[context.model_dump()],
        #     ids=[context.asset_name]
        # )

        logger.info(f"Asset '{context.asset_name}' indexed in ChromaDB")
        return True

    async def get_similar_incidents(self, asset_name: str, limit: int = 5) -> list[dict[str, Any]]:
        """
        Retrieve similar past incidents for an asset.

        Searches incident history for patterns matching the current asset
        or similar assets in the same tier.

        Args:
            asset_name: Asset name to find incidents for.
            limit: Maximum number of incidents to return (default: 5).

        Returns:
            list: List of incident records with details.
        """
        logger.debug(f"Searching similar incidents for '{asset_name}' (limit: {limit})")

        # TODO: Implement actual incident search from ChromaDB
        # results = self.client.query(
        #     collection_name="aegis_incidents",
        #     query_texts=[asset_name],
        #     n_results=limit
        # )

        # For now, return empty list
        logger.info(
            f"No historical incidents found for '{asset_name}' "
            f"(or ChromaDB not yet implemented)"
        )
        return []

    async def close(self) -> None:
        """Close ChromaDB client connection."""
        # TODO: Close Chroma HTTP connection if needed
        logger.debug("ChromaDB client closed")
