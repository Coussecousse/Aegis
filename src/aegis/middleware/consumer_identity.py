"""Dedicated RabbitMQ consumer for identity synchronization messages."""

from __future__ import annotations

import asyncio
import json
import logging
import os
from urllib.parse import quote

import aio_pika
from aio_pika.abc import (
    AbstractChannel,
    AbstractIncomingMessage,
    AbstractQueue,
    AbstractRobustConnection,
)

from aegis.rag.client import ChromaDBClient
from aegis.rag.ldap import LdapConfig, LdapConnector
from aegis.vault.loader import load_secrets_to_env

logger = logging.getLogger(__name__)


class RabbitMQIdentityConsumer:
    """Async RabbitMQ worker dedicated to identity synchronization."""

    def __init__(
        self,
        rabbitmq_host: str = "localhost",
        rabbitmq_port: int = 5672,
        rabbitmq_user: str = "guest",
        rabbitmq_password: str | None = None,
        rabbitmq_vhost: str = "aegis",
        queue_name: str = "identity.sync",
        chromadb_host: str = "localhost",
        chromadb_port: int = 8000,
        ldap_host: str = "localhost",
        ldap_base_dn: str = "DC=aerotech,DC=local",
        ldap_bind_dn: str = "",
        ldap_bind_password: str = "",
        ldap_timeout: float = 5.0,
        ldap_tier0_group_dn: str = "CN=Domain Admins,CN=Users,DC=aerotech,DC=local",
        ldap_use_ssl: bool = True,
        ldap_port: int = 0,
    ) -> None:
        """Initialize dedicated identity synchronization consumer.

        Args:
            rabbitmq_host: RabbitMQ server hostname.
            rabbitmq_port: RabbitMQ server port.
            rabbitmq_user: RabbitMQ username.
            rabbitmq_password: RabbitMQ password.
            rabbitmq_vhost: RabbitMQ virtual host.
            queue_name: Queue name for identity sync messages.
            chromadb_host: ChromaDB server hostname.
            chromadb_port: ChromaDB server port.
            ldap_host: LDAP server hostname.
            ldap_base_dn: LDAP base DN.
            ldap_bind_dn: LDAP bind DN for read-only account.
            ldap_bind_password: LDAP bind password.
            ldap_timeout: LDAP timeout in seconds.
            ldap_tier0_group_dn: Full DN of the Tier 0 group (Domain Admins).
        """
        self.rabbitmq_host = rabbitmq_host
        self.rabbitmq_port = rabbitmq_port
        self.rabbitmq_user = rabbitmq_user
        self.rabbitmq_password = rabbitmq_password
        self.rabbitmq_vhost = rabbitmq_vhost
        self.queue_name = queue_name

        self.chromadb_host = chromadb_host
        self.chromadb_port = chromadb_port

        self.ldap_config = LdapConfig(
            host=ldap_host,
            base_dn=ldap_base_dn,
            bind_dn=ldap_bind_dn,
            bind_password=ldap_bind_password,
            timeout=ldap_timeout,
            tier0_group_dn=ldap_tier0_group_dn,
            use_ssl=ldap_use_ssl,
            port=ldap_port,
        )

        self.connection: AbstractRobustConnection | None = None
        self.channel: AbstractChannel | None = None
        self.queue: AbstractQueue | None = None

    async def connect(self) -> None:
        """Establish connection to RabbitMQ and bind to identity queue."""
        encoded_user = quote(self.rabbitmq_user or "", safe="")
        encoded_password = quote(self.rabbitmq_password or "", safe="")
        encoded_vhost = quote(self.rabbitmq_vhost or "/", safe="")
        connection_url = (
            f"amqp://{encoded_user}:{encoded_password}"
            f"@{self.rabbitmq_host}:{self.rabbitmq_port}/{encoded_vhost}"
        )

        self.connection = await aio_pika.connect_robust(connection_url)
        self.channel = await self.connection.channel()
        self.queue = await self.channel.declare_queue(self.queue_name, passive=True)

    async def start(self) -> None:
        """Start consuming identity synchronization jobs indefinitely."""
        chromadb_client = ChromaDBClient(self.chromadb_host, self.chromadb_port)
        connector = LdapConnector(self.ldap_config)

        async with chromadb_client:
            while True:
                try:
                    await self.connect()
                    if self.queue is None:
                        raise RuntimeError("Identity queue is not initialized")

                    async with self.queue.iterator() as queue_iter:
                        async for message in queue_iter:
                            await self._handle_message(message, chromadb_client, connector)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    logger.warning(f"Identity consumer loop interrupted, reconnecting: {exc}")
                    await self.close()
                    await asyncio.sleep(2.0)

    async def _handle_message(
        self,
        message: AbstractIncomingMessage,
        chromadb_client: ChromaDBClient,
        connector: LdapConnector,
    ) -> None:
        """Handle a single identity synchronization message.

        Args:
            message: Incoming RabbitMQ message.
            chromadb_client: Initialized ChromaDB client.
            connector: LDAPS identity connector.
        """
        try:
            payload = json.loads(message.body.decode("utf-8"))
            if not isinstance(payload, dict):
                raise ValueError("Identity payload must be a JSON object")

            asset_id_raw = payload.get("asset_id") or payload.get("source_ip")
            if not isinstance(asset_id_raw, str) or not asset_id_raw:
                raise ValueError("Identity payload must include a non-empty asset_id or source_ip")

            success = await chromadb_client.sync_asset_identity(asset_id_raw, connector)
            if success:
                await message.ack()
            else:
                await message.nack(requeue=False)

        except json.JSONDecodeError:
            logger.error("Invalid JSON payload received in identity.sync queue")
            await message.ack()
        except ValueError as exc:
            logger.error(f"Invalid identity payload: {exc}")
            await message.ack()
        except Exception as exc:
            logger.error(f"Unexpected identity sync error: {exc}")
            await message.nack(requeue=False)

    async def close(self) -> None:
        """Close RabbitMQ connection for the identity consumer."""
        if self.connection is not None:
            await self.connection.close()
            self.connection = None
            self.channel = None
            self.queue = None


def build_identity_consumer_from_env() -> RabbitMQIdentityConsumer:
    """Build an identity consumer instance from environment variables.

    Returns:
        RabbitMQIdentityConsumer configured from environment.
    """
    load_secrets_to_env()

    return RabbitMQIdentityConsumer(
        rabbitmq_host=os.getenv("RABBITMQ_HOST", "localhost"),
        rabbitmq_port=int(os.getenv("RABBITMQ_PORT", "5672")),
        rabbitmq_user=os.getenv("RABBITMQ_USER", "guest"),
        rabbitmq_password=os.getenv("RABBITMQ_PASSWORD", "guest"),
        rabbitmq_vhost=os.getenv("RABBITMQ_VHOST", "aegis"),
        queue_name=os.getenv("RABBITMQ_IDENTITY_QUEUE", "identity.sync"),
        chromadb_host=os.getenv("CHROMADB_HOST", "localhost"),
        chromadb_port=int(os.getenv("CHROMADB_PORT", "8000")),
        ldap_host=os.getenv("LDAP_HOST", "localhost"),
        ldap_base_dn=os.getenv("LDAP_BASE_DN", "DC=aerotech,DC=local"),
        ldap_bind_dn=os.getenv("LDAP_BIND_DN", ""),
        ldap_bind_password=os.getenv("LDAP_BIND_PASSWORD", ""),
        ldap_timeout=float(os.getenv("LDAP_TIMEOUT", "5.0")),
        ldap_tier0_group_dn=os.getenv(
            "LDAP_TIER0_GROUP_DN", "CN=Domain Admins,CN=Users,DC=aerotech,DC=local"
        ),
        ldap_use_ssl=os.getenv("LDAP_USE_SSL", "false").lower() == "true",
        ldap_port=int(os.getenv("LDAP_PORT", "0")),
    )
