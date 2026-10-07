from __future__ import annotations

import pytest

from adsec.collectors.ldap.collector import LdapCollector
from adsec.collectors.ldap.normalizer import normalize_ldap_collection
from adsec.core.models.engagement import Scope
from adsec.core.models.enums import AccessLevel, Severity
from adsec.core.scope.scope_manager import ScopeManager
from adsec.credentials.provider import AnonymousCredentialProvider
from adsec.rules.acl.ad_acl_001_generic_all import GenericAllOnPrivilegedObject
from adsec.rules.acl.ad_acl_002_write_dacl_owner import WriteDaclOrOwnerOnPrivilegedObject
from adsec.rules.acl.ad_acl_003_force_change_password import ForceChangePasswordOnPrivilegedAccount
from adsec.rules.acl.ad_acl_004_generic_write import GenericWriteOnPrivilegedObject
from adsec.rules.acl.well_known_sids import is_well_known_safe_trustee
from adsec.rules.base import NormalizedData, ScanContext
from adsec.rules.trusts.ad_trust_001_no_sid_filtering import ExternalTrustWithoutSidFiltering
from tests.fixtures.corp_example import (
    DC_HOSTNAME,
    SID_AUTH_USERS,
    SID_BOB,
    SID_HELPDESK,
    SID_SVC_SQL,
    build_mock_connection,
)

CTX = ScanContext("ENG-1", "JOB-1", AccessLevel.AUTHENTICATED, "standard")


@pytest.fixture()
async def data() -> NormalizedData:
    collector = LdapCollector(
        ScopeManager(Scope(engagement_id="ENG-1", domains=["corp.example"])),
        AnonymousCredentialProvider(),
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
            "trusts": [t.model_dump() for t in norm.trusts],
        },
    )


def test_well_known_trustees() -> None:
    assert is_well_known_safe_trustee("S-1-5-18")
    assert is_well_known_safe_trustee("S-1-5-21-1-2-3-512")
    assert is_well_known_safe_trustee("S-1-5-32-544")
    assert not is_well_known_safe_trustee("S-1-1-0")
    assert not is_well_known_safe_trustee("S-1-5-11")
    assert not is_well_known_safe_trustee("S-1-5-21-1-2-3-1105")
    assert not is_well_known_safe_trustee(None)


async def test_generic_all_flags_only_non_default_trustee_on_privileged_object(
    data: NormalizedData,
) -> None:
    findings = await GenericAllOnPrivilegedObject().run(CTX, data)
    assert (
        len(findings) == 1
    )  # Helpdesk sur Alice ; pas Domain Admins/SYSTEM, pas Bob (non sensible)
    f = findings[0]
    assert f.rule_id == "AD-ACL-001"
    assert f.principal == SID_HELPDESK
    assert "Alice Admin" in f.affected_assets[0]
    assert f.severity == Severity.HIGH
    assert f.evidence and f.evidence[0].attribute == "nTSecurityDescriptor"
    assert f.mitre_technique_id is None


async def test_write_owner_flagged_on_privileged_group(data: NormalizedData) -> None:
    findings = await WriteDaclOrOwnerOnPrivilegedObject().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].principal == SID_BOB
    assert "Domain Admins" in findings[0].affected_assets[0]


async def test_force_change_password_flagged(data: NormalizedData) -> None:
    findings = await ForceChangePasswordOnPrivilegedAccount().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].principal == SID_SVC_SQL


async def test_generic_write_by_broad_principal_is_critical(data: NormalizedData) -> None:
    findings = await GenericWriteOnPrivilegedObject().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].principal == SID_AUTH_USERS
    assert findings[0].severity == Severity.CRITICAL


async def test_rules_do_not_double_report_full_control(data: NormalizedData) -> None:
    # Le GenericAll de Helpdesk (AD-ACL-001) ne doit pas ressortir en 002/004.
    assert not [
        f
        for f in await WriteDaclOrOwnerOnPrivilegedObject().run(CTX, data)
        if f.principal == SID_HELPDESK
    ]
    assert not [
        f
        for f in await GenericWriteOnPrivilegedObject().run(CTX, data)
        if f.principal == SID_HELPDESK
    ]


async def test_trust_without_sid_filtering_only_for_external_trust(data: NormalizedData) -> None:
    findings = await ExternalTrustWithoutSidFiltering().run(CTX, data)
    assert len(findings) == 1  # partner.example ; le trust de foret est ecarte
    assert findings[0].affected_assets == ["partner.example"]
    assert findings[0].confidence.value == "medium"


async def test_no_findings_without_acl_data() -> None:
    empty = NormalizedData(engagement_id="ENG-1", tables={})
    assert await GenericAllOnPrivilegedObject().run(CTX, empty) == []
    assert await ExternalTrustWithoutSidFiltering().run(CTX, empty) == []
