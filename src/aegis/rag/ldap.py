"""LDAPS identity connector for Active Directory context extraction."""

from __future__ import annotations

import asyncio
import importlib
import logging
from dataclasses import dataclass
from typing import Literal

from aegis.middleware.models import RagContext, UEBAMetrics
from aegis.rag.base import BaseIdentityConnector

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class LdapConfig:
    """Configuration for LDAP/LDAPS identity extraction.

    Args:
        host: LDAP server hostname.
        base_dn: LDAP search base DN.
        bind_dn: LDAP bind DN for the read-only service account.
        bind_password: LDAP bind password.
        port: LDAP port. Defaults to 636 when use_ssl=True, 389 otherwise.
        use_ssl: Enable LDAPS (TLS). Set to False for plain LDAP (POC/dev).
        timeout: Connection and query timeout in seconds.
        tier0_group_dn: Full DN of the group considered Tier 0 (Domain Admins).
            Override this for environments that differ from the default domain.
    """

    host: str
    base_dn: str
    bind_dn: str
    bind_password: str
    use_ssl: bool = True
    port: int = 0
    timeout: float = 5.0
    tier0_group_dn: str = "CN=Domain Admins,CN=Users,DC=aerotech,DC=local"

    def __post_init__(self) -> None:
        """Set default port based on use_ssl when port is unset."""
        if self.port == 0:
            object.__setattr__(self, "port", 636 if self.use_ssl else 389)


class LdapConnector(BaseIdentityConnector):
    """Fetch identity context from Active Directory over LDAPS."""

    def __init__(self, config: LdapConfig) -> None:
        """Initialize the LDAPS connector.

        Args:
            config: Typed LDAPS configuration.
        """
        self.config = config

    async def fetch_identity_context(self, asset_identifier: str) -> RagContext:
        """Fetch identity and privilege layout for a given asset identifier.

        Args:
            asset_identifier: The IP address, hostname, or unique asset ID.

        Returns:
            RagContext filled with target environment metadata.

        Raises:
            ConnectionError: If the remote identity store is unreachable.
        """
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(self._fetch_identity_context_blocking, asset_identifier),
                timeout=self.config.timeout,
            )
        except TimeoutError as exc:
            raise ConnectionError("LDAPS query timed out") from exc
        except ConnectionError:
            raise
        except Exception as exc:
            raise ConnectionError("Failed to query LDAPS identity store") from exc

    def _fetch_identity_context_blocking(self, asset_identifier: str) -> RagContext:
        """Run the LDAP query synchronously in a thread-safe wrapper.

        Args:
            asset_identifier: Asset lookup key.

        Returns:
            RagContext built from LDAP attributes.

        Raises:
            ConnectionError: If LDAP bind or search fails.
        """
        try:
            ldap3_module = importlib.import_module("ldap3")
        except ModuleNotFoundError as exc:
            raise ConnectionError("ldap3 dependency is not installed") from exc

        server = ldap3_module.Server(
            self.config.host,
            port=self.config.port,
            use_ssl=self.config.use_ssl,
            connect_timeout=self.config.timeout,
            get_info=ldap3_module.NONE,
        )

        connection = ldap3_module.Connection(
            server,
            user=self.config.bind_dn,
            password=self.config.bind_password,
            auto_bind=ldap3_module.AUTO_BIND_NO_TLS,
            receive_timeout=int(self.config.timeout),
            read_only=True,
            raise_exceptions=False,
        )

        # AD-style filter with sAMAccountName; falls back to cn-only for plain LDAP.
        ad_filter = (
            f"(|(sAMAccountName={asset_identifier})"
            f"(dNSHostName={asset_identifier})"
            f"(cn={asset_identifier}))"
        )
        fallback_filter = f"(cn={asset_identifier})"

        found = connection.search(
            search_base=self.config.base_dn,
            search_filter=ad_filter,
            attributes=ldap3_module.ALL_ATTRIBUTES,
            size_limit=1,
        )
        if not found and connection.result.get("description") == "invalidAttributeSyntax":
            connection.search(
                search_base=self.config.base_dn,
                search_filter=fallback_filter,
                attributes=ldap3_module.ALL_ATTRIBUTES,
                size_limit=1,
            )

        if not connection.entries:
            connection.unbind()
            return self._default_context(asset_identifier)

        entry = connection.entries[0]

        distinguished_name = getattr(entry, "entry_dn", None) or self._extract_scalar_attribute(
            entry, "distinguishedName"
        )
        account_name = self._extract_scalar_attribute(
            entry, "sAMAccountName"
        ) or self._extract_scalar_attribute(entry, "cn")
        # memberOf is an operational attribute absent from plain OpenLDAP; fall back to a
        # reverse membership lookup against the tier0 group using the BASE scope.
        groups = self._extract_list_attribute(entry, "memberOf")
        if not groups and distinguished_name:
            connection.search(
                search_base=self.config.tier0_group_dn,
                search_filter=f"(member={distinguished_name})",
                search_scope=ldap3_module.BASE,
                attributes=[],
                size_limit=1,
            )
            if connection.entries:
                groups = [self.config.tier0_group_dn]

        connection.unbind()

        criticality: Literal["tier0", "tier2"]
        criticality = "tier0" if self._is_tier0(groups, self.config.tier0_group_dn) else "tier2"
        description = (
            f"Identity context from LDAPS for {account_name or asset_identifier} "
            f"({distinguished_name or 'unknown DN'})"
        )

        return RagContext(
            asset_name=account_name or asset_identifier,
            asset_criticality=criticality,
            asset_description=description,
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description="Identity baseline from Active Directory",
                associated_users=[account_name] if account_name else [],
                normal_activity_window="Unknown",
                recent_anomalies=groups,
                # Privilege is carried by asset_criticality (tier) + the risk scorer's
                # criticality multiplier — NOT by anomaly_score. anomaly_score is a
                # purely behavioral signal that accrues from observed activity
                # (see aegis.rag.ueba / PostgresIdentityStore.record_activity), so a freshly
                # synced asset starts at 0.0 until its behavior says otherwise.
                anomaly_score=0.0,
            ),
        )

    @staticmethod
    def _extract_scalar_attribute(entry: object, attr_name: str) -> str:
        """Extract a scalar LDAP attribute as string.

        Args:
            entry: LDAP entry object.
            attr_name: Attribute name to read.

        Returns:
            Extracted string value, empty when unavailable.
        """
        attr = getattr(entry, attr_name, None)
        value = getattr(attr, "value", "")
        return str(value) if value is not None else ""

    @staticmethod
    def _extract_list_attribute(entry: object, attr_name: str) -> list[str]:
        """Extract a list LDAP attribute as a list of strings.

        Args:
            entry: LDAP entry object.
            attr_name: Attribute name to read.

        Returns:
            Extracted string list, empty when unavailable.
        """
        attr = getattr(entry, attr_name, None)
        values = getattr(attr, "values", [])
        if not isinstance(values, list):
            return []
        return [str(item) for item in values]

    @staticmethod
    def _is_tier0(groups: list[str], tier0_group_dn: str) -> bool:
        """Determine whether identity groups map to Tier 0 criticality.

        Args:
            groups: LDAP group DN list.
            tier0_group_dn: Full DN of the Tier 0 reference group.

        Returns:
            True when the reference group DN is found in the groups list.
        """
        normalized = {group.lower() for group in groups}
        return tier0_group_dn.lower() in normalized

    @staticmethod
    def _default_context(asset_identifier: str) -> RagContext:
        """Build a restrictive fallback context for unknown identities.

        Args:
            asset_identifier: Identity lookup key.

        Returns:
            Restrictive Tier 2 context.
        """
        return RagContext(
            asset_name=asset_identifier,
            asset_criticality="tier2",
            asset_description="Identity context unavailable from LDAPS",
            similar_incidents=[],
            ueba=UEBAMetrics(
                baseline_description="No identity baseline",
                associated_users=[],
                normal_activity_window="Unknown",
                recent_anomalies=[],
                anomaly_score=0.0,
            ),
        )
