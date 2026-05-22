"""Runtime helper to load HashiCorp Vault secrets into process environment."""

from __future__ import annotations

import asyncio
import os

from aegis.vault.client import VaultClient


def load_secrets_to_env() -> bool:
    """Load Vault secrets into ``os.environ`` when Vault is configured.

    If ``VAULT_ADDR`` is absent, this function is a no-op and returns ``False``.
    If Vault is configured but unreachable or invalid, a ``RuntimeError`` is raised.

    Returns:
        ``True`` when Vault loading is active, otherwise ``False``.
    """
    vault_addr = os.getenv("VAULT_ADDR", "").strip()
    if not vault_addr:
        return False

    vault_token = os.getenv("VAULT_TOKEN", "").strip()
    if not vault_token:
        raise RuntimeError("Vault is configured but VAULT_TOKEN is missing")

    vault_mount = os.getenv("VAULT_KV_MOUNT", "secret")
    vault_path = os.getenv("VAULT_KV_PATH", "aegis")
    vault_namespace = os.getenv("VAULT_NAMESPACE") or None
    vault_timeout = float(os.getenv("VAULT_TIMEOUT", "5.0"))

    client = VaultClient(
        addr=vault_addr,
        token=vault_token,
        kv_mount=vault_mount,
        kv_path=vault_path,
        timeout=vault_timeout,
        namespace=vault_namespace,
    )

    async def _load() -> dict[str, str]:
        return await client.get_all_secrets()

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        try:
            secrets = asyncio.run(_load())
        except (ConnectionError, PermissionError, KeyError, ValueError) as exc:
            raise RuntimeError(f"Vault loading failed: {exc}") from exc
    else:
        raise RuntimeError("Vault loading must run before starting the asyncio event loop")

    for key, value in secrets.items():
        os.environ[key] = value

    return True
