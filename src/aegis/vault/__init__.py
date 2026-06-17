"""HashiCorp Vault package exports for AEGIS runtime secret loading."""

from __future__ import annotations

from aegis.vault.client import VaultClient
from aegis.vault.loader import load_secrets_to_env

__all__ = ["VaultClient", "load_secrets_to_env"]
