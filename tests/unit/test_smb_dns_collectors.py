from __future__ import annotations

import pytest

from adsec.collectors.dns.collector import DnsCollector
from adsec.collectors.smb.collector import SmbCollector
from adsec.core.models.engagement import Scope
from adsec.core.models.enums import AccessLevel
from adsec.core.scope.scope_manager import OutOfScopeError, ScopeManager
from adsec.credentials.provider import AnonymousCredentialProvider
from tests.fixtures.fake_dns import build_fake_dns_probe, build_hardened_dns_probe
from tests.fixtures.fake_smb import build_fake_smb_session, build_hardened_smb_session

SCOPE = Scope(engagement_id="E", domains=["corp.example"])


@pytest.fixture()
def smb_collector() -> SmbCollector:
    return SmbCollector(
        ScopeManager(SCOPE), AnonymousCredentialProvider(), session_factory=build_fake_smb_session
    )


async def test_smb_discover_reports_smb1_and_no_signing(smb_collector: SmbCollector) -> None:
    result = await smb_collector.discover("dc01.corp.example")
    assert result.access_level_achieved == AccessLevel.ANONYMOUS
    assert result.facts["is_smb1"] is True
    assert result.facts["signing_required"] is False
    assert result.facts["guest_or_anonymous"] is True


async def test_smb_discover_hardened_host() -> None:
    collector = SmbCollector(
        ScopeManager(SCOPE),
        AnonymousCredentialProvider(),
        session_factory=build_hardened_smb_session,
    )
    result = await collector.discover("dc01.corp.example")
    assert result.facts["is_smb1"] is False
    assert result.facts["signing_required"] is True
    assert result.facts["guest_or_anonymous"] is False


async def test_smb_collect_excludes_ipc_from_probe_but_flags_public(
    smb_collector: SmbCollector,
) -> None:
    result = await smb_collector.collect("dc01.corp.example")
    shares = {s["name"]: s for s in result.objects["shares"]}
    assert shares["IPC$"]["anonymous_readable"] is False  # exclu du test (partage cache)
    assert shares["Public"]["anonymous_readable"] is True
    assert shares["NETLOGON"]["anonymous_readable"] is False
    assert shares["C$"]["is_hidden_admin_share"] is True


async def test_smb_out_of_scope_refused() -> None:
    collector = SmbCollector(
        ScopeManager(SCOPE), AnonymousCredentialProvider(), session_factory=build_fake_smb_session
    )
    with pytest.raises(OutOfScopeError):
        await collector.discover("evil.com")
    with pytest.raises(OutOfScopeError):
        await collector.collect("evil.com")


@pytest.fixture()
def dns_collector() -> DnsCollector:
    return DnsCollector(ScopeManager(SCOPE), probe_factory=build_fake_dns_probe)


async def test_dns_discover_reachable(dns_collector: DnsCollector) -> None:
    result = await dns_collector.discover("dc01.corp.example")
    assert result.facts["reachable"] is True
    assert not result.partial


async def test_dns_collect_zone_transfer_and_recursion(dns_collector: DnsCollector) -> None:
    result = await dns_collector.collect("dc01.corp.example", "corp.example")
    check = result.objects["dns_zone_checks"][0]
    assert check["zone_transfer_allowed"] is True
    assert check["zone_transfer_record_count"] == 37
    assert check["recursion_available"] is True


async def test_dns_collect_hardened_server() -> None:
    collector = DnsCollector(ScopeManager(SCOPE), probe_factory=build_hardened_dns_probe)
    result = await collector.collect("dc01.corp.example", "corp.example")
    check = result.objects["dns_zone_checks"][0]
    assert check["zone_transfer_allowed"] is False
    assert check["recursion_available"] is False


async def test_dns_out_of_scope_refused(dns_collector: DnsCollector) -> None:
    with pytest.raises(OutOfScopeError):
        await dns_collector.discover("evil.com")
