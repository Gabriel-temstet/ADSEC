from __future__ import annotations

from adsec.core.models.enums import AccessLevel, Severity
from adsec.rules.base import NormalizedData, ScanContext
from adsec.rules.dns.checks import OpenRecursion, ZoneTransferAllowed
from adsec.rules.smb.checks import (
    ShareReadableAnonymously,
    Smb1Enabled,
    SmbNullSessionAllowed,
    SmbSigningNotRequired,
)

CTX = ScanContext("ENG-1", "JOB-1", AccessLevel.ANONYMOUS, "standard")

SMB_HOST_VULNERABLE = {
    "hostname": "dc01.corp.example",
    "dialect": "NT LM 0.12",
    "is_smb1": True,
    "signing_required": False,
    "guest_or_anonymous": True,
    "shares": [
        {"name": "IPC$", "remark": "", "is_hidden_admin_share": True, "anonymous_readable": False},
        {
            "name": "Public",
            "remark": "",
            "is_hidden_admin_share": False,
            "anonymous_readable": True,
        },
        {
            "name": "NETLOGON",
            "remark": "",
            "is_hidden_admin_share": False,
            "anonymous_readable": False,
        },
    ],
}

SMB_HOST_HARDENED = {
    "hostname": "srv02.corp.example",
    "dialect": "0x0302",
    "is_smb1": False,
    "signing_required": True,
    "guest_or_anonymous": False,
    "shares": [
        {"name": "IPC$", "remark": "", "is_hidden_admin_share": True, "anonymous_readable": False},
    ],
}


def _data(*hosts: dict[str, object], dc_hostnames: list[str] | None = None) -> NormalizedData:
    computers = (
        [{"dns_hostname": h, "raw_attrs": {"userAccountControl": 0x2000}} for h in dc_hostnames]
        if dc_hostnames
        else []
    )
    return NormalizedData(
        engagement_id="ENG-1", tables={"smb_hosts": list(hosts), "computers": computers}
    )


async def test_smb1_flagged_only_for_vulnerable_host() -> None:
    findings = await Smb1Enabled().run(CTX, _data(SMB_HOST_VULNERABLE, SMB_HOST_HARDENED))
    assert len(findings) == 1
    assert findings[0].principal == "dc01.corp.example"
    assert findings[0].severity == Severity.HIGH


async def test_signing_not_required_is_high_on_domain_controller() -> None:
    findings = await SmbSigningNotRequired().run(
        CTX, _data(SMB_HOST_VULNERABLE, dc_hostnames=["dc01.corp.example"])
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH  # cible = DC


async def test_signing_not_required_is_medium_on_non_dc() -> None:
    host = {**SMB_HOST_VULNERABLE, "hostname": "fileserver.corp.example"}
    findings = await SmbSigningNotRequired().run(
        CTX, _data(host, dc_hostnames=["dc01.corp.example"])
    )
    assert len(findings) == 1
    assert findings[0].severity == Severity.MEDIUM


async def test_hardened_host_has_no_signing_finding() -> None:
    findings = await SmbSigningNotRequired().run(CTX, _data(SMB_HOST_HARDENED))
    assert findings == []


async def test_null_session_flagged() -> None:
    findings = await SmbNullSessionAllowed().run(CTX, _data(SMB_HOST_VULNERABLE, SMB_HOST_HARDENED))
    assert len(findings) == 1
    assert findings[0].principal == "dc01.corp.example"


async def test_share_readable_anonymously_excludes_hidden_and_unreadable() -> None:
    findings = await ShareReadableAnonymously().run(CTX, _data(SMB_HOST_VULNERABLE))
    assert len(findings) == 1
    assert "Public" in findings[0].title
    assert "IPC$" not in findings[0].title


async def test_no_smb_findings_on_empty_data() -> None:
    empty = NormalizedData(engagement_id="ENG-1", tables={})
    assert await Smb1Enabled().run(CTX, empty) == []
    assert await SmbSigningNotRequired().run(CTX, empty) == []
    assert await SmbNullSessionAllowed().run(CTX, empty) == []
    assert await ShareReadableAnonymously().run(CTX, empty) == []


ZONE_VULNERABLE = {
    "zone": "corp.example",
    "zone_transfer_allowed": True,
    "zone_transfer_record_count": 42,
    "recursion_available": True,
}
ZONE_HARDENED = {
    "zone": "corp.example",
    "zone_transfer_allowed": False,
    "zone_transfer_record_count": 0,
    "recursion_available": False,
}


async def test_zone_transfer_allowed_flagged() -> None:
    data = NormalizedData(engagement_id="ENG-1", tables={"dns_zone_checks": [ZONE_VULNERABLE]})
    findings = await ZoneTransferAllowed().run(CTX, data)
    assert len(findings) == 1
    assert "42" in findings[0].description


async def test_zone_transfer_not_flagged_when_refused() -> None:
    data = NormalizedData(engagement_id="ENG-1", tables={"dns_zone_checks": [ZONE_HARDENED]})
    assert await ZoneTransferAllowed().run(CTX, data) == []


async def test_open_recursion_flagged() -> None:
    data = NormalizedData(engagement_id="ENG-1", tables={"dns_zone_checks": [ZONE_VULNERABLE]})
    findings = await OpenRecursion().run(CTX, data)
    assert len(findings) == 1
    assert findings[0].severity == Severity.LOW


async def test_no_dns_findings_on_empty_data() -> None:
    empty = NormalizedData(engagement_id="ENG-1", tables={})
    assert await ZoneTransferAllowed().run(CTX, empty) == []
    assert await OpenRecursion().run(CTX, empty) == []
