"""Identity-synchronization processor for the AEGIS pipeline.

Behind :class:`MessageConsumer` (queue ``identity.sync``): for each job, resolve
an asset identifier and sync its identity context from LDAP into ChromaDB. A
transient failure dead-letters (``on_error="dead_letter"``) rather than
requeueing forever — identity enrichment is best-effort, not the alert path.
"""

from __future__ import annotations

import logging
from contextlib import AsyncExitStack
from typing import Any

from aegis.config import Settings
from aegis.middleware.message_consumer import (
    MessageConsumer,
    Publisher,
    UnprocessableMessageError,
)
from aegis.rag.client import ChromaDBClient
from aegis.rag.ldap import LdapConfig, LdapConnector

logger = logging.getLogger(__name__)


class IdentityProcessor:
    """Sync one asset's identity context from LDAP into ChromaDB."""

    def __init__(
        self,
        *,
        chromadb_host: str = "localhost",
        chromadb_port: int = 8000,
        ldap_config: LdapConfig,
    ) -> None:
        self.chromadb_host = chromadb_host
        self.chromadb_port = chromadb_port
        self.ldap_config = ldap_config

        self._stack: AsyncExitStack | None = None
        self._chroma: ChromaDBClient | None = None
        self._connector: LdapConnector | None = None

    async def __aenter__(self) -> IdentityProcessor:
        stack = AsyncExitStack()
        self._chroma = await stack.enter_async_context(
            ChromaDBClient(self.chromadb_host, self.chromadb_port)
        )
        self._connector = LdapConnector(self.ldap_config)
        self._stack = stack
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        if self._stack is not None:
            await self._stack.aclose()

    async def process(self, payload: dict[str, Any], publish: Publisher) -> None:
        """Sync identity for one job (publish is unused for this stage)."""
        _ = publish
        if self._chroma is None or self._connector is None:
            raise RuntimeError("IdentityProcessor used outside its context manager")

        asset_id_raw = payload.get("asset_id") or payload.get("source_ip")
        if not isinstance(asset_id_raw, str) or not asset_id_raw:
            raise UnprocessableMessageError("identity payload needs a non-empty asset_id/source_ip")

        success = await self._chroma.sync_asset_identity(asset_id_raw, self._connector)
        if not success:
            # Transient (LDAP/ChromaDB) failure → dead-letter per the consumer policy.
            raise RuntimeError(f"identity sync failed for asset_id={asset_id_raw!r}")


def build_identity_consumer(settings: Settings) -> MessageConsumer:
    """Build the identity MessageConsumer from settings."""
    ldap = settings.ldap
    ldap_config = LdapConfig(
        host=ldap.host,
        base_dn=ldap.base_dn,
        bind_dn=ldap.bind_dn,
        bind_password=ldap.bind_password,
        timeout=ldap.timeout,
        tier0_group_dn=ldap.tier0_group_dn,
        use_ssl=ldap.use_ssl,
        port=ldap.port,
    )
    processor = IdentityProcessor(
        chromadb_host=settings.chroma.host,
        chromadb_port=settings.chroma.port,
        ldap_config=ldap_config,
    )
    rmq = settings.rabbitmq
    return MessageConsumer(
        amqp_url=rmq.amqp_url,
        queue_name=rmq.identity_queue,
        processor=processor,
        on_error="dead_letter",
    )
