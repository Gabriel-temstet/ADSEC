from __future__ import annotations

import pytest

from adsec.collectors.ldap.collector import LdapCollector
from adsec.collectors.ldap.normalizer import normalize_ldap_collection
from adsec.core.models.engagement import Scope
from adsec.core.models.enums import AccessLevel, CredentialType, Severity
from adsec.core.scope.scope_manager import ScopeManager
from adsec.credentials.provider import Credential, StaticCredentialProvider
from adsec.rules.acl.ad_acl_005_replication_rights import ReplicationRightsOnDomain
from adsec.rules.base import NormalizedData, ScanContext
from adsec.rules.gpo.checks import GpoWritableByNonAdmin, UnlinkedGpo
from adsec.rules.kerberos.checks import (
    AsRepRoastable,
    ConstrainedDelegationProtocolTransition,
    Kerberoastable,
    ResourceBasedConstrainedDelegation,
    UnconstrainedDelegation,
    WeakKerberosEncryption,
)
from tests.fixtures.corp_example import (
    DC_HOSTNAME,
    SID_BOB,
    SID_WEBSRV01,
    build_mock_connection,
)

CTX = ScanContext("ENG-1", "JOB-1", AccessLevel.AUTHENTICATED, "standard")
AUTH_CREDS = StaticCredentialProvider(
    Credential(CredentialType.USER, principal="CN=audit,CN=Users,DC=corp,DC=example", secret="x")
)


@pytest.fixture()
async def data() -> NormalizedData:
    collector = LdapCollector(
        ScopeManager(Scope(engagement_id="ENG-1", domains=["corp.example"])),
        AUTH_CREDS,
        connection_factory=build_mock_connection,
    )
    await collector.discover(DC_HOSTNAME)
    result = await collector.collect(DC_HOSTNAME)
    norm = normalize_ldap_collection("ENG-1", "DOM-1", result)
    return NormalizedData(
        engagement_id="ENG-1",
        tables={
            "users": [u.model_dump() for u in norm.users],
            "groups": [g.model_dump() for g in norm.groups],
            "computers": [c.model_dump() for c in norm.computers],
            "acls": [a.model_dump() for a in norm.acls],
            "gpos": [g.model_dump() for g in norm.gpos],
            "trusts": [t.model_dump() for t in norm.trusts],
        },
    )


async def test_asrep_roastable_detects_legacy_svc_only(data: NormalizedData) -> None:
    findings = await AsRepRoastable().run(CTX, data)
    names = {f.title for f in findings}
    assert len(findings) == 1
    assert any("legacy-svc" in t for t in names)
    assert findings[0].mitre_technique_id == "T1558.004"


async def test_kerberoastable_detects_spn_accounts_not_krbtgt(data: NormalizedData) -> None:
    findings = await Kerberoastable().run(CTX, data)
    names = {f.title for f in findings}
    assert len(findings) == 2
    assert any("svc-sql" in t for t in names)
    assert any("svc-backup" in t for t in names)
    assert not any("krbtgt" in t.lower() for t in names)


async def test_unconstrained_delegation_excludes_domain_controllers(data: NormalizedData) -> None:
    findings = await UnconstrainedDelegation().run(CTX, data)
    assert len(findings) == 1
    assert "APPSRV01" in findings[0].title
    assert not any("DC01" in f.title for f in findings)


async def test_constrained_delegation_to_dc_is_high_severity(data: NormalizedData) -> None:
    findings = await ConstrainedDelegationProtocolTransition().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].principal == SID_WEBSRV01
    assert findings[0].severity == Severity.HIGH  # une cible est le DC (cifs/dc01...)


async def test_rbcd_detected_on_filesrv01(data: NormalizedData) -> None:
    findings = await ResourceBasedConstrainedDelegation().run(CTX, data)
    assert len(findings) == 1
    assert "FILESRV01" in findings[0].title
    assert SID_WEBSRV01 in findings[0].evidence[0].value


async def test_weak_encryption_flags_des_only_and_no_aes(data: NormalizedData) -> None:
    findings = await WeakKerberosEncryption().run(CTX, data)
    titles = {f.title: f.severity for f in findings}
    assert any("svc-backup" in t for t in titles)  # USE_DES_KEY_ONLY -> HIGH
    assert any("svc-sql" in t for t in titles)  # encryption types=0 -> MEDIUM
    des_finding = next(f for t, f in [(t, s) for t, s in titles.items()] if "svc-backup" in t)
    assert des_finding == Severity.HIGH


async def test_replication_rights_flags_bob_as_complete_dcsync(data: NormalizedData) -> None:
    findings = await ReplicationRightsOnDomain().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].principal == SID_BOB
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].confidence.value == "high"  # get-changes + get-changes-all = complet


async def test_gpo_writable_flags_critical_scope(data: NormalizedData) -> None:
    findings = await GpoWritableByNonAdmin().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].principal == SID_BOB
    assert findings[0].severity == Severity.CRITICAL  # liee a la racine du domaine
    assert "Default Domain Policy" in findings[0].title


async def test_unlinked_gpo_detects_orphan_only(data: NormalizedData) -> None:
    findings = await UnlinkedGpo().run(CTX, data)
    assert len(findings) == 1
    assert "Orphaned Legacy Policy" in findings[0].title


async def test_no_findings_on_empty_data() -> None:
    empty = NormalizedData(engagement_id="ENG-1", tables={})
    assert await AsRepRoastable().run(CTX, empty) == []
    assert await Kerberoastable().run(CTX, empty) == []
    assert await UnconstrainedDelegation().run(CTX, empty) == []
    assert await ConstrainedDelegationProtocolTransition().run(CTX, empty) == []
    assert await ResourceBasedConstrainedDelegation().run(CTX, empty) == []
    assert await WeakKerberosEncryption().run(CTX, empty) == []
    assert await ReplicationRightsOnDomain().run(CTX, empty) == []
    assert await GpoWritableByNonAdmin().run(CTX, empty) == []
    assert await UnlinkedGpo().run(CTX, empty) == []
