"""HashiCorp Vault KV v2 client for runtime secret retrieval."""

from __future__ import annotations

from typing import Any

import httpx


class VaultClient:
    """KV v2 client via ``httpx`` for on-premise Vault."""

    def __init__(
        self,
        addr: str,
        token: str,
        kv_mount: str = "secret",
        kv_path: str = "aegis",
        timeout: float = 5.0,
        namespace: str | None = None,
    ) -> None:
        """Initialize Vault client settings.

        Args:
            addr: Vault base URL.
            token: Vault token used for ``X-Vault-Token`` auth.
            kv_mount: KV engine mount path.
            kv_path: Secret path under the mount.
            timeout: HTTP request timeout in seconds.
            namespace: Optional Vault Enterprise namespace.
        """
        self.addr = addr.rstrip("/")
        self.token = token
        self.kv_mount = kv_mount.strip("/")
        self.kv_path = kv_path.strip("/")
        self.timeout = timeout
        self.namespace = namespace

    def _build_url(self) -> str:
        """Build KV v2 read endpoint URL."""
        return f"{self.addr}/v1/{self.kv_mount}/data/{self.kv_path}"

    def _build_headers(self) -> dict[str, str]:
        """Build mandatory Vault headers."""
        headers = {"X-Vault-Token": self.token}
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        return headers

    async def get_all_secrets(self) -> dict[str, str]:
        """Return all secrets from the configured KV v2 path.

        Raises:
            PermissionError: If token is forbidden.
            KeyError: If secret path does not exist.
            ConnectionError: If network or protocol errors occur.
        """
        url = self._build_url()
        headers = self._build_headers()

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise ConnectionError("Failed to reach Vault API") from exc

        if response.status_code == 403:
            raise PermissionError("Vault access denied (403)")
        if response.status_code == 404:
            raise KeyError("Vault KV path not found")
        if response.status_code >= 400:
            raise ConnectionError(f"Vault API returned status {response.status_code}")

        try:
            payload = response.json()
        except ValueError as exc:
            raise ConnectionError("Vault API returned invalid JSON") from exc

        return self._extract_secret_map(payload)

    async def get_secret(self, key: str) -> str:
        """Return one secret value from the configured KV v2 path.

        Args:
            key: Secret key to read under ``data.data``.

        Raises:
            PermissionError: If token is forbidden.
            KeyError: If path or key is missing.
            ConnectionError: If network or protocol errors occur.
        """
        secrets = await self.get_all_secrets()
        if key not in secrets:
            raise KeyError(f"Vault key not found: {key}")
        return secrets[key]

    @staticmethod
    def _extract_secret_map(payload: dict[str, Any]) -> dict[str, str]:
        """Extract ``data.data`` as a string map from Vault response."""
        data_obj = payload.get("data")
        if not isinstance(data_obj, dict):
            raise KeyError("Vault response missing data object")

        secrets_obj = data_obj.get("data")
        if not isinstance(secrets_obj, dict):
            raise KeyError("Vault response missing data.data object")

        result: dict[str, str] = {}
        for raw_key, raw_value in secrets_obj.items():
            result[str(raw_key)] = str(raw_value)
        return result
