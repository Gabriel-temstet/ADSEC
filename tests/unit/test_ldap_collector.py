from __future__ import annotations

import pytest

from adsec.collectors.ldap.collector import LdapCollector
from adsec.collectors.ldap.normalizer import normalize_ldap_collection
from adsec.core.models.engagement import Scope
from adsec.core.models.enums import AccessLevel
from adsec.core.scope.scope_manager import OutOfScopeError, ScopeManager
from adsec.credentials.provider import AnonymousCredentialProvider
from tests.fixtures.corp_example import DC_HOSTNAME, build_mock_connection


@pytest.fixture()
def collector() -> LdapCollector:
    scope = Scope(engagement_id="ENG-test", domains=["corp.example"])
    return LdapCollector(
        ScopeManager(scope),
        AnonymousCredentialProvider(),
        connection_factory=build_mock_connection,
    )


async def test_discover_reads_root_dse(collector: LdapCollector) -> None:
    result = await collector.discover(DC_HOSTNAME)
    assert result.access_level_achieved == AccessLevel.ANONYMOUS
    assert result.facts["domain_fqdn"] == "corp.example"
    assert result.facts["naming_context"] == "DC=corp,DC=example"
    assert result.facts["dns_hostname"] == DC_HOSTNAME


async def test_out_of_scope_target_is_refused_before_any_connection() -> None:
    calls: list[str] = []

    def factory(*args: object) -> object:
        calls.append("called")
        raise AssertionError("aucune connexion ne doit etre ouverte hors scope")

    scope = Scope(engagement_id="ENG-test", domains=["corp.example"])
    collector = LdapCollector(
        ScopeManager(scope),
        AnonymousCredentialProvider(),
        connection_factory=factory,  # type: ignore[arg-type]
    )
    with pytest.raises(OutOfScopeError):
        await collector.discover("dc.evil.com")
    with pytest.raises(OutOfScopeError):
        await collector.collect("dc.evil.com")
    assert calls == []


async def test_collect_counts(collector: LdapCollector) -> None:
    result = await collector.collect(DC_HOSTNAME)
    assert result.errors == []
    assert result.count("users") == 6
    assert result.count("groups") == 2
    assert result.count("computers") == 4
    assert result.count("ous") == 2


async def test_normalization_flags_and_memberships(collector: LdapCollector) -> None:
    await collector.discover(DC_HOSTNAME)
    result = await collector.collect(DC_HOSTNAME)
    norm = normalize_ldap_collection("ENG-test", "DOM-test", result)

    users = {u.sam_account_name: u for u in norm.users}
    assert users["alice.admin"].admin_count is True
    assert users["legacy-svc"].pre_auth_not_required is True
    assert users["svc-sql"].spns == ["MSSQLSvc/sqlsrv01.corp.example:1433"]
    assert users["svc-sql"].password_never_expires is True
    assert users["old.employee"].enabled is False
    assert users["bob.user"].enabled is True

    computers = {c.sam_account_name: c for c in norm.computers}
    assert computers["APPSRV01$"].unconstrained_delegation is True
    assert computers["DC01$"].unconstrained_delegation is True  # DC reel : comportement normal

    groups = {g.sam_account_name: g for g in norm.groups}
    assert groups["Domain Admins"].privileged is True
    assert groups["Helpdesk Tier2"].privileged is False

    types = {
        (m.group_dn.split(",")[0], m.member_dn.split(",")[0]): m.member_type
        for m in norm.memberships
    }
    assert types[("CN=Domain Admins", "CN=Alice Admin")] == "user"
    assert types[("CN=Domain Admins", "CN=Helpdesk Tier2")] == "group"
    assert types[("CN=Helpdesk Tier2", "CN=Bob User")] == "user"
