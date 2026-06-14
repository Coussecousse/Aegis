"""Identity-synchronization processor for the AEGIS pipeline.

Behind :class:`MessageConsumer` (queue ``identity.sync``): for each job, resolve
an asset identifier and sync its identity context from LDAP into ChromaDB. A
transient failure dead-letters (``on_error="dead_letter"``) rather than
requeueing forever — identity enrichment is best-effort, not the alert path.
"""

from __future__ import annotations

import logging
import os
from contextlib import AsyncExitStack
from typing import Any

from aegis.middleware.message_consumer import (
    MessageConsumer,
    Publisher,
    UnprocessableMessageError,
    build_amqp_url,
)
from aegis.rag.client import ChromaDBClient
from aegis.rag.ldap import LdapConfig, LdapConnector
from aegis.vault.loader import load_secrets_to_env

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


def build_identity_consumer_from_env() -> MessageConsumer:
    """Build the identity MessageConsumer from environment variables."""
    load_secrets_to_env()
    ldap_config = LdapConfig(
        host=os.getenv("LDAP_HOST", "localhost"),
        base_dn=os.getenv("LDAP_BASE_DN", "DC=aerotech,DC=local"),
        bind_dn=os.getenv("LDAP_BIND_DN", ""),
        bind_password=os.getenv("LDAP_BIND_PASSWORD", ""),
        timeout=float(os.getenv("LDAP_TIMEOUT", "5.0")),
        tier0_group_dn=os.getenv(
            "LDAP_TIER0_GROUP_DN", "CN=Domain Admins,CN=Users,DC=aerotech,DC=local"
        ),
        use_ssl=os.getenv("LDAP_USE_SSL", "false").lower() == "true",
        port=int(os.getenv("LDAP_PORT", "0")),
    )
    processor = IdentityProcessor(
        chromadb_host=os.getenv("CHROMADB_HOST", "localhost"),
        chromadb_port=int(os.getenv("CHROMADB_PORT", "8000")),
        ldap_config=ldap_config,
    )
    return MessageConsumer(
        amqp_url=build_amqp_url(
            os.getenv("RABBITMQ_HOST", "localhost"),
            int(os.getenv("RABBITMQ_PORT", "5672")),
            os.getenv("RABBITMQ_USER", "guest"),
            os.getenv("RABBITMQ_PASSWORD", "guest"),
            os.getenv("RABBITMQ_VHOST", "aegis"),
        ),
        queue_name=os.getenv("RABBITMQ_IDENTITY_QUEUE", "identity.sync"),
        processor=processor,
        on_error="dead_letter",
    )
