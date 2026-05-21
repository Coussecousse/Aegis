"""HashiCorp Vault client interface for AEGIS secrets management."""

from __future__ import annotations


class VaultClient:
    """Async Vault client interface.

    Vault integration is intentionally deferred when no Vault instance is available
    in the current environment.
    """

    async def get_secret(self, path: str, key: str) -> str:
        """Get a secret value from Vault.

        Args:
            path: Vault secret path.
            key: Key inside the secret object.

        Returns:
            str: Secret value.

        Raises:
            NotImplementedError: Raised when Vault is not deployed.
        """
        _ = path
        _ = key
        raise NotImplementedError("Vault not deployed")

    async def rotate_key(self, path: str) -> None:
        """Rotate a key in Vault.

        Args:
            path: Vault secret path.

        Raises:
            NotImplementedError: Raised when Vault is not deployed.
        """
        _ = path
        raise NotImplementedError("Vault not deployed")
