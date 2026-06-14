"""Wazuh alert parsing and forwarding to RabbitMQ exchange."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from uuid import uuid4

import aio_pika
from aio_pika.abc import AbstractChannel, AbstractExchange, AbstractRobustConnection
from pydantic import ValidationError

from aegis.config import build_amqp_url
from aegis.middleware.models import WazuhLog

logger = logging.getLogger(__name__)


class WazuhAlertParser:
    """Parse raw Wazuh alert payloads into validated ``WazuhLog`` models."""

    @staticmethod
    def parse_alert(
        payload: dict[str, Any],
        min_level: int = 7,
        excluded_rules: frozenset[int] = frozenset(),
    ) -> WazuhLog | None:
        """Map a Wazuh JSON alert into a validated ``WazuhLog`` instance.

        Args:
            payload: Raw Wazuh alert JSON object.
            min_level: Minimum ``rule.level`` required to forward the alert.
            excluded_rules: Rule ids to drop as known noise (e.g. host
                self-monitoring like netstat port changes). Filtering by rule —
                not by agent — because a single Wazuh agent here covers both the
                AEGIS infra host and the monitored targets, so excluding the
                agent would blind real detections.

        Returns:
            ``WazuhLog`` when mapping succeeds and threshold is met, otherwise ``None``.
        """
        timestamp = payload.get("timestamp")
        rule = payload.get("rule")
        agent = payload.get("agent")

        if (
            not isinstance(timestamp, str)
            or not isinstance(rule, dict)
            or not isinstance(agent, dict)
        ):
            return None

        rule_id = WazuhAlertParser._to_int(rule.get("id"))
        rule_level = WazuhAlertParser._to_int(rule.get("level"))
        rule_description = rule.get("description")
        source_agent = agent.get("name")

        source_ip_raw = agent.get("ip")
        if not isinstance(source_ip_raw, str) or not source_ip_raw:
            source_ip_raw = WazuhAlertParser._read_nested_string(payload, "data", "srcip")

        # Real actor IP: data.srcip is the remote client (e.g. a web attacker), distinct
        # from the agent host IP. Surface it so the report cites the attacker, not the host.
        data_srcip = WazuhAlertParser._read_nested_string(payload, "data", "srcip")
        attacker_ip = data_srcip if data_srcip and data_srcip != source_ip_raw else None

        full_log = payload.get("full_log")

        if (
            rule_id is None
            or rule_level is None
            or not isinstance(rule_description, str)
            or not rule_description
            or not isinstance(source_agent, str)
            or not source_agent
            or not isinstance(source_ip_raw, str)
            or not source_ip_raw
            or not isinstance(full_log, str)
            or not full_log
        ):
            return None

        if rule_level < min_level:
            return None

        # Docker's own networking activity: dockerd legitimately enables
        # promiscuous mode on veth interfaces when creating container networks
        # (rule 80710). The auditd `comm="dockerd"` signature in the log itself
        # — not the agent or the rule alone — is what distinguishes this from a
        # genuine sniffing attempt, so detection stays intact for every other
        # process, device, and host.
        if rule_id == 80710 and 'comm="dockerd"' in full_log:
            return None

        # Wazuh operational rules: agent lifecycle events, not security alerts
        _operational_rules = {501, 502, 503, 510, 511, 512, 513}
        if rule_id in _operational_rules:
            return None

        # Operator-configured noise (e.g. infra host self-monitoring): drop early
        # so it never consumes an LLM analysis cycle.
        if rule_id in excluded_rules:
            return None

        mitre_technique = WazuhAlertParser._extract_mitre_technique(payload)
        decoder_name = WazuhAlertParser._read_nested_string(payload, "decoder", "name")

        try:
            return WazuhLog(
                id=uuid4(),
                timestamp=WazuhAlertParser._parse_timestamp(timestamp),
                rule_id=rule_id,
                rule_level=rule_level,
                rule_description=rule_description,
                source_agent=source_agent,
                source_ip=source_ip_raw,
                attacker_ip=attacker_ip,
                full_log=full_log,
                decoder_name=decoder_name,
                mitre_technique=mitre_technique,
            )
        except (ValidationError, ValueError):
            return None

    @staticmethod
    def _to_int(value: object) -> int | None:
        """Convert arbitrary values to int safely."""
        if isinstance(value, bool) or value is None:
            return None
        if isinstance(value, int):
            return value
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                return None
        if isinstance(value, float):
            return int(value)
        return None

    @staticmethod
    def _read_nested_string(payload: dict[str, Any], parent: str, child: str) -> str | None:
        """Read nested ``payload[parent][child]`` as a non-empty string."""
        parent_obj = payload.get(parent)
        if not isinstance(parent_obj, dict):
            return None
        value = parent_obj.get(child)
        if isinstance(value, str) and value:
            return value
        return None

    @staticmethod
    def _extract_mitre_technique(payload: dict[str, Any]) -> str | None:
        """Extract the first MITRE technique identifier from Wazuh payload."""
        mitre_obj = payload.get("mitre")
        if not isinstance(mitre_obj, dict):
            return None
        techniques = mitre_obj.get("technique")
        if isinstance(techniques, list) and techniques:
            first = techniques[0]
            if isinstance(first, str) and first:
                return first
        return None

    @staticmethod
    def _parse_timestamp(value: str) -> datetime:
        """Parse Wazuh timestamp strings into timezone-aware datetimes."""
        normalized = value
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"

        if len(normalized) >= 5 and normalized[-5] in {"+", "-"} and normalized[-3] != ":":
            normalized = normalized[:-2] + ":" + normalized[-2:]

        return datetime.fromisoformat(normalized)


@dataclass
class WazuhForwarder:
    """Forward parsed Wazuh alerts to RabbitMQ."""

    rabbitmq_host: str = "localhost"
    rabbitmq_port: int = 5672
    rabbitmq_user: str = "guest"
    rabbitmq_password: str = "guest"
    rabbitmq_vhost: str = "aegis"
    exchange_name: str = "aegis.alerts"
    routing_key: str = "alert.raw"
    min_level: int = 7
    excluded_rules: frozenset[int] = frozenset()

    def __post_init__(self) -> None:
        """Initialize non-dataclass runtime attributes."""
        self._connection: AbstractRobustConnection | None = None
        self._channel: AbstractChannel | None = None
        self._exchange: AbstractExchange | None = None

    async def connect(self) -> None:
        """Establish RabbitMQ connection and resolve destination exchange."""
        connection_url = build_amqp_url(
            self.rabbitmq_host,
            self.rabbitmq_port,
            self.rabbitmq_user,
            self.rabbitmq_password,
            self.rabbitmq_vhost,
        )

        self._connection = await aio_pika.connect_robust(connection_url)
        self._channel = await self._connection.channel()
        self._exchange = await self._channel.get_exchange(self.exchange_name, ensure=True)

    async def close(self) -> None:
        """Close RabbitMQ connection if opened."""
        if self._connection is not None:
            await self._connection.close()
            self._connection = None
            self._channel = None
            self._exchange = None

    async def forward_alert(self, payload: dict[str, Any]) -> bool:
        """Parse and publish one alert when it passes threshold rules.

        Args:
            payload: Raw Wazuh JSON payload.

        Returns:
            ``True`` when a message was published, ``False`` when skipped or invalid.
        """
        parsed = WazuhAlertParser.parse_alert(
            payload, min_level=self.min_level, excluded_rules=self.excluded_rules
        )
        if parsed is None:
            return False

        if self._exchange is None:
            raise RuntimeError("WazuhForwarder is not connected")

        body = json.dumps(parsed.model_dump(mode="json")).encode("utf-8")
        message = aio_pika.Message(body=body, content_type="application/json")
        await self._exchange.publish(message, routing_key=self.routing_key)
        logger.debug(
            "Forwarded Wazuh alert rule_id=%s level=%s source_ip=%s",
            parsed.rule_id,
            parsed.rule_level,
            parsed.source_ip,
        )
        return True
