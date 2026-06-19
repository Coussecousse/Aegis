"""Typed application settings, read from the environment exactly once.

Before this, every entrypoint and consumer builder re-read the same env vars
with raw ``os.getenv`` — the RabbitMQ block alone was duplicated four times,
with defaults drifting between call sites. ``Settings.from_env()`` is the single
place that answers "what does AEGIS read from the environment?": the field list
is the env contract (it mirrors ``.env.example``), parsing/defaults are hidden.

Scope: the wiring layer (connections, URLs, timeouts, thresholds). The
pipeline's model-name constants stay in ``pipeline.py`` to avoid threading them
through ``triage_log`` / ``analyze_log`` signatures.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from urllib.parse import quote


def build_amqp_url(host: str, port: int, user: str, password: str | None, vhost: str) -> str:
    """Build a percent-encoded amqp:// URL from connection parts."""
    encoded_user = quote(user or "", safe="")
    encoded_password = quote(password or "", safe="")
    encoded_vhost = quote(vhost or "/", safe="")
    return f"amqp://{encoded_user}:{encoded_password}@{host}:{port}/{encoded_vhost}"


def _excluded_rules(raw: str) -> frozenset[int]:
    """Parse a comma-separated rule-id list into ints (bad entries skipped)."""
    rules: set[int] = set()
    for token in raw.split(","):
        token = token.strip()
        if token:
            try:
                rules.add(int(token))
            except ValueError:
                continue
    return frozenset(rules)


@dataclass(frozen=True)
class RabbitMQSettings:
    """RabbitMQ connection and queue/exchange names."""

    host: str = "localhost"
    port: int = 5672
    user: str = "guest"
    password: str = "guest"
    vhost: str = "aegis"
    triage_queue: str = "aegis.triage"
    reports_queue: str = "aegis.reports"
    identity_queue: str = "identity.sync"
    exchange: str = "aegis.alerts"

    @property
    def amqp_url(self) -> str:
        """The percent-encoded amqp:// connection URL for these settings."""
        return build_amqp_url(self.host, self.port, self.user, self.password, self.vhost)

    @classmethod
    def from_env(cls) -> RabbitMQSettings:
        return cls(
            host=os.getenv("RABBITMQ_HOST", "localhost"),
            port=int(os.getenv("RABBITMQ_PORT", "5672")),
            user=os.getenv("RABBITMQ_USER", "guest"),
            password=os.getenv("RABBITMQ_PASSWORD", "guest"),
            vhost=os.getenv("RABBITMQ_VHOST", "aegis"),
            triage_queue=os.getenv("RABBITMQ_QUEUE", "aegis.triage"),
            reports_queue=os.getenv("RABBITMQ_REPORTS_QUEUE", "aegis.reports"),
            identity_queue=os.getenv("RABBITMQ_IDENTITY_QUEUE", "identity.sync"),
            exchange=os.getenv("RABBITMQ_EXCHANGE", "aegis.alerts"),
        )


@dataclass(frozen=True)
class OllamaSettings:
    """Ollama instance URLs, model names, per-stage timeouts, and decoding mode."""

    slm_base_url: str = "http://10.0.0.1:11434"
    llm_base_url: str = "http://10.0.0.1:11435"
    slm_model: str = "qwen25-aegis"
    llm_model: str = "mistral-aegis"
    slm_timeout: float = 10.0
    llm_timeout: float = 45.0
    use_schema: bool = False

    @classmethod
    def from_env(cls) -> OllamaSettings:
        return cls(
            slm_base_url=os.getenv("OLLAMA_SLM_BASE_URL", "http://10.0.0.1:11434"),
            llm_base_url=os.getenv("OLLAMA_LLM_BASE_URL", "http://10.0.0.1:11435"),
            slm_model=os.getenv("SLM_MODEL", "qwen25-aegis"),
            llm_model=os.getenv("LLM_MODEL", "mistral-aegis"),
            slm_timeout=float(os.getenv("SLM_TIMEOUT", "10.0")),
            llm_timeout=float(os.getenv("LLM_TIMEOUT", "45.0")),
            use_schema=os.getenv("LLM_USE_SCHEMA", "false").strip().lower() == "true",
        )


@dataclass(frozen=True)
class PostgresSettings:
    """PostgreSQL connection."""

    host: str = "localhost"
    port: int = 5432
    database: str = "aegis"
    user: str = "aegis_app"
    password: str = ""

    @classmethod
    def from_env(cls) -> PostgresSettings:
        return cls(
            host=os.getenv("POSTGRES_HOST", "localhost"),
            port=int(os.getenv("POSTGRES_PORT", "5432")),
            database=os.getenv("POSTGRES_DB", "aegis"),
            user=os.getenv("POSTGRES_USER", "aegis_app"),
            password=os.getenv("POSTGRES_PASSWORD", ""),
        )


@dataclass(frozen=True)
class LdapSettings:
    """LDAP/LDAPS identity-connector configuration."""

    host: str = "localhost"
    base_dn: str = "DC=aerotech,DC=local"
    bind_dn: str = ""
    bind_password: str = ""
    timeout: float = 5.0
    tier0_group_dn: str = "CN=Domain Admins,CN=Users,DC=aerotech,DC=local"
    use_ssl: bool = False
    port: int = 0

    @classmethod
    def from_env(cls) -> LdapSettings:
        return cls(
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


@dataclass(frozen=True)
class WazuhSettings:
    """Wazuh alert collector configuration."""

    alerts_file: str = "/var/ossec/logs/alerts/alerts.json"
    min_level: int = 7
    excluded_rules: frozenset[int] = field(default_factory=frozenset)
    poll_interval: float = 1.0

    @classmethod
    def from_env(cls) -> WazuhSettings:
        return cls(
            alerts_file=os.getenv("WAZUH_ALERTS_FILE", "/var/ossec/logs/alerts/alerts.json"),
            min_level=int(os.getenv("WAZUH_MIN_LEVEL", "7")),
            excluded_rules=_excluded_rules(os.getenv("WAZUH_EXCLUDED_RULES", "")),
            poll_interval=float(os.getenv("WAZUH_POLL_INTERVAL", "1.0")),
        )


@dataclass(frozen=True)
class Settings:
    """Top-level application settings, assembled once from the environment."""

    rabbitmq: RabbitMQSettings = field(default_factory=RabbitMQSettings)
    ollama: OllamaSettings = field(default_factory=OllamaSettings)
    postgres: PostgresSettings = field(default_factory=PostgresSettings)
    ldap: LdapSettings = field(default_factory=LdapSettings)
    wazuh: WazuhSettings = field(default_factory=WazuhSettings)
    suspicion_threshold: float = 0.5
    fp_gate_confidence_ceiling: float = 0.6
    response_policy_file: str | None = None
    shuffle_webhook_url: str = "http://shuffle:3001/api/v1/hooks/"
    log_level: str = "INFO"

    @classmethod
    def from_env(cls) -> Settings:
        return cls(
            rabbitmq=RabbitMQSettings.from_env(),
            ollama=OllamaSettings.from_env(),
            postgres=PostgresSettings.from_env(),
            ldap=LdapSettings.from_env(),
            wazuh=WazuhSettings.from_env(),
            suspicion_threshold=float(os.getenv("SUSPICION_THRESHOLD", "0.5")),
            fp_gate_confidence_ceiling=float(os.getenv("FP_GATE_CONFIDENCE_CEILING", "0.6")),
            response_policy_file=os.getenv("RESPONSE_POLICY_FILE") or None,
            shuffle_webhook_url=os.getenv(
                "SHUFFLE_WEBHOOK_URL", "http://shuffle:3001/api/v1/hooks/"
            ),
            log_level=os.getenv("LOG_LEVEL", "INFO"),
        )
