"""Unit tests for the LDAPS identity connector."""

from __future__ import annotations

import pytest

from aegis.identity_store.ldap import LdapConfig, LdapConnector


class _FakeLdapAttribute:
    def __init__(self, value: str | None = None, values: list[str] | None = None) -> None:
        self.value = value
        self.values = values or []


class _FakeLdapEntry:
    def __init__(self) -> None:
        self.distinguishedName = _FakeLdapAttribute(
            value="CN=admin-user,CN=Users,DC=aerotech,DC=local"
        )
        self.sAMAccountName = _FakeLdapAttribute(value="admin-user")
        self.memberOf = _FakeLdapAttribute(
            values=["CN=Domain Admins,CN=Users,DC=aerotech,DC=local"]
        )


class _FakeLdapConnection:
    def __init__(self, *args: object, **kwargs: object) -> None:
        _ = args
        _ = kwargs
        self.entries: list[object] = [_FakeLdapEntry()]
        self.result: dict[str, str] = {}

    def search(self, **kwargs: object) -> bool:
        _ = kwargs
        return True

    def unbind(self) -> None:
        return None


class _FakeLdapServer:
    def __init__(self, *args: object, **kwargs: object) -> None:
        _ = args
        _ = kwargs


class _FakeLdapModule:
    Server = _FakeLdapServer
    Connection = _FakeLdapConnection
    NONE = "NONE"
    ALL_ATTRIBUTES = "*"
    AUTO_BIND_NO_TLS = "AUTO_BIND_NO_TLS"


@pytest.mark.asyncio
async def test_fetch_identity_context_maps_tier0(monkeypatch: pytest.MonkeyPatch) -> None:
    config = LdapConfig(
        host="ldap.local",
        base_dn="DC=aerotech,DC=local",
        bind_dn="CN=svc_ldap,OU=Svc,DC=aerotech,DC=local",
        bind_password="unused-in-test",  # pragma: allowlist secret
        tier0_group_dn="CN=Domain Admins,CN=Users,DC=aerotech,DC=local",
    )
    connector = LdapConnector(config)

    target = "aegis.identity_store.ldap.importlib.import_module"
    monkeypatch.setattr(target, lambda _: _FakeLdapModule())

    context = await connector.fetch_identity_context("dc-01")

    assert context.asset_criticality == "tier0"
    assert context.asset_name == "admin-user"
    assert "CN=Domain Admins,CN=Users,DC=aerotech,DC=local" in context.ueba.recent_anomalies


@pytest.mark.asyncio
async def test_fetch_identity_context_timeout_raises_connection_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = LdapConfig(
        host="ldap.local",
        base_dn="DC=aerotech,DC=local",
        bind_dn="CN=svc_ldap,OU=Svc,DC=aerotech,DC=local",
        bind_password="unused-in-test",  # pragma: allowlist secret
        timeout=5.0,
    )
    connector = LdapConnector(config)

    async def _fake_to_thread(*args: object, **kwargs: object) -> object:
        _ = args
        _ = kwargs
        raise TimeoutError

    monkeypatch.setattr("aegis.identity_store.ldap.asyncio.to_thread", _fake_to_thread)

    with pytest.raises(ConnectionError):
        await connector.fetch_identity_context("dc-01")


@pytest.mark.asyncio
async def test_fetch_identity_context_tier0_custom_dn(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tier0 detection works when tier0_group_dn uses a non-default CN=Builtin container."""

    class _FakeEntryBuiltin:
        def __init__(self) -> None:
            self.distinguishedName = _FakeLdapAttribute(  # noqa: N815
                value="CN=admin,CN=Users,DC=corp,DC=example"
            )
            self.sAMAccountName = _FakeLdapAttribute(value="admin")  # noqa: N815
            self.memberOf = _FakeLdapAttribute(  # noqa: N815
                values=["CN=Domain Admins,CN=Builtin,DC=corp,DC=example"]
            )

    class _FakeConnectionBuiltin(_FakeLdapConnection):
        def __init__(self, *args: object, **kwargs: object) -> None:
            super().__init__(*args, **kwargs)
            self.entries = [_FakeEntryBuiltin()]

    class _FakeModuleBuiltin:
        Server = _FakeLdapServer
        Connection = _FakeConnectionBuiltin
        NONE = "NONE"
        ALL_ATTRIBUTES = "*"
        AUTO_BIND_NO_TLS = "AUTO_BIND_NO_TLS"

    config = LdapConfig(
        host="ldap.corp",
        base_dn="DC=corp,DC=example",
        bind_dn="CN=svc,OU=Svc,DC=corp,DC=example",
        bind_password="unused-in-test",  # pragma: allowlist secret
        tier0_group_dn="CN=Domain Admins,CN=Builtin,DC=corp,DC=example",
    )
    connector = LdapConnector(config)

    target = "aegis.identity_store.ldap.importlib.import_module"
    monkeypatch.setattr(target, lambda _: _FakeModuleBuiltin())

    context = await connector.fetch_identity_context("dc-01")

    assert context.asset_criticality == "tier0"
