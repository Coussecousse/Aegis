"""Unit tests for Vault KV v2 client and environment loader."""

from __future__ import annotations

import pytest

from aegis.vault.client import VaultClient
from aegis.vault.loader import load_secrets_to_env


class _FakeResponse:
    def __init__(self, status_code: int, payload: dict[str, object]) -> None:
        self.status_code = status_code
        self._payload = payload

    def json(self) -> dict[str, object]:
        return self._payload


class _FakeAsyncClient:
    def __init__(self, responses: list[_FakeResponse]) -> None:
        self._responses = responses

    async def __aenter__(self) -> _FakeAsyncClient:
        return self

    async def __aexit__(self, exc_type: object, exc_val: object, exc_tb: object) -> None:
        _ = exc_type
        _ = exc_val
        _ = exc_tb

    async def get(self, url: str, headers: dict[str, str]) -> _FakeResponse:
        _ = url
        _ = headers
        return self._responses.pop(0)


@pytest.mark.asyncio
async def test_get_secret_success(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _FakeResponse(
        status_code=200,
        payload={
            "data": {
                "data": {
                    "RABBITMQ_PASSWORD": "rabbit-secret",  # pragma: allowlist secret
                }
            }
        },
    )

    monkeypatch.setattr(
        "aegis.vault.client.httpx.AsyncClient",
        lambda timeout: _FakeAsyncClient([response]),
    )

    client = VaultClient(addr="https://vault.local:8200", token="token")
    value = await client.get_secret("RABBITMQ_PASSWORD")

    assert value == "rabbit-secret"


@pytest.mark.asyncio
async def test_get_secret_forbidden_raises_permission_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    response = _FakeResponse(status_code=403, payload={})
    monkeypatch.setattr(
        "aegis.vault.client.httpx.AsyncClient",
        lambda timeout: _FakeAsyncClient([response]),
    )

    client = VaultClient(addr="https://vault.local:8200", token="token")

    with pytest.raises(PermissionError):
        await client.get_secret("RABBITMQ_PASSWORD")


@pytest.mark.asyncio
async def test_get_secret_not_found_raises_key_error(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _FakeResponse(status_code=404, payload={})
    monkeypatch.setattr(
        "aegis.vault.client.httpx.AsyncClient",
        lambda timeout: _FakeAsyncClient([response]),
    )

    client = VaultClient(addr="https://vault.local:8200", token="token")

    with pytest.raises(KeyError):
        await client.get_secret("RABBITMQ_PASSWORD")


@pytest.mark.asyncio
async def test_get_all_secrets_returns_full_dict(monkeypatch: pytest.MonkeyPatch) -> None:
    response = _FakeResponse(
        status_code=200,
        payload={"data": {"data": {"A": "1", "B": "2"}}},
    )
    monkeypatch.setattr(
        "aegis.vault.client.httpx.AsyncClient",
        lambda timeout: _FakeAsyncClient([response]),
    )

    client = VaultClient(addr="https://vault.local:8200", token="token")
    secrets = await client.get_all_secrets()

    assert secrets == {"A": "1", "B": "2"}


def test_loader_skips_when_vault_addr_not_set(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("VAULT_ADDR", raising=False)
    monkeypatch.setattr(
        "aegis.vault.client.httpx.AsyncClient",
        lambda timeout: pytest.fail("httpx client should not be called"),
    )

    active = load_secrets_to_env()

    assert active is False
