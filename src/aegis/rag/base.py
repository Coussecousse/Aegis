"""Abstract interfaces for identity context connectors used by the RAG layer."""

from __future__ import annotations

from abc import ABC, abstractmethod

from aegis.middleware.models import RagContext


class BaseIdentityConnector(ABC):
    """Abstract base class for identity store extraction (ETL paradigm)."""

    @abstractmethod
    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        """Fetch identity and privilege layout for a given asset identifier.

        Args:
            asset_identifier: The IP address, hostname, or unique asset ID.

        Returns:
            RagContext filled with target environment metadata.

        Raises:
            ConnectionError: If the remote identity store is unreachable.
        """
        raise NotImplementedError
