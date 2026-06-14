"""Unit tests for the typed Settings module."""

from __future__ import annotations

import pytest

from aegis.config import Settings


def test_settings_defaults_when_env_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "RABBITMQ_HOST",
        "RABBITMQ_PORT",
        "RABBITMQ_QUEUE",
        "CHROMADB_PORT",
        "WAZUH_EXCLUDED_RULES",
        "SUSPICION_THRESHOLD",
    ):
        monkeypatch.delenv(key, raising=False)

    settings = Settings.from_env()

    assert settings.rabbitmq.host == "localhost"
    assert settings.rabbitmq.port == 5672
    assert settings.rabbitmq.triage_queue == "aegis.triage"
    assert settings.rabbitmq.exchange == "aegis.alerts"
    assert settings.chroma.port == 8000
    assert settings.wazuh.excluded_rules == frozenset()
    assert settings.suspicion_threshold == 0.5


def test_settings_reads_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("RABBITMQ_HOST", "rabbit.internal")
    monkeypatch.setenv("RABBITMQ_PORT", "5673")
    monkeypatch.setenv("CHROMADB_PORT", "9000")
    monkeypatch.setenv("SUSPICION_THRESHOLD", "0.7")
    monkeypatch.setenv("SLM_MODEL", "qwen25-llm-aegis")
    monkeypatch.setenv("LLM_MODEL", "mistral-custom")
    monkeypatch.setenv("LLM_USE_SCHEMA", "true")

    settings = Settings.from_env()

    assert settings.rabbitmq.host == "rabbit.internal"
    assert settings.rabbitmq.port == 5673
    assert settings.chroma.port == 9000
    assert settings.suspicion_threshold == 0.7
    assert settings.ollama.slm_model == "qwen25-llm-aegis"
    assert settings.ollama.llm_model == "mistral-custom"
    assert settings.ollama.use_schema is True


def test_rabbitmq_amqp_url_percent_encodes_credentials() -> None:
    from aegis.config import RabbitMQSettings

    rmq = RabbitMQSettings(host="rabbitmq", port=5672, user="u", password="p@ss!", vhost="aegis")

    assert rmq.amqp_url == "amqp://u:p%40ss%21@rabbitmq:5672/aegis"  # pragma: allowlist secret


def test_settings_excluded_rules_parsing(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("WAZUH_EXCLUDED_RULES", "533, 80710 , notanint, ")

    settings = Settings.from_env()

    assert settings.wazuh.excluded_rules == frozenset({533, 80710})
