from __future__ import annotations

from adsec.collectors.ldap.attributes import (
    UAC_DONT_REQ_PREAUTH,
    as_list,
    decode_sid,
    filetime_to_iso,
    is_account_enabled,
    naming_context_to_fqdn,
    rdn_and_parent,
    uac_has_flag,
)


def test_naming_context_to_fqdn() -> None:
    assert naming_context_to_fqdn("DC=corp,DC=example") == "corp.example"
    assert naming_context_to_fqdn("DC=a,DC=b,DC=c") == "a.b.c"


def test_rdn_and_parent() -> None:
    assert rdn_and_parent("OU=Users,DC=corp,DC=example") == ("Users", "DC=corp,DC=example")
    assert rdn_and_parent("DC=corp") == ("corp", None)


def test_uac_flags() -> None:
    assert is_account_enabled(512)
    assert not is_account_enabled(514)
    assert is_account_enabled(None)
    assert uac_has_flag(4194816, UAC_DONT_REQ_PREAUTH)
    assert not uac_has_flag(512, UAC_DONT_REQ_PREAUTH)
    assert not uac_has_flag(None, UAC_DONT_REQ_PREAUTH)


def test_decode_sid() -> None:
    # S-1-5-21-1-2-3-500
    raw = bytes([1, 5, 0, 0, 0, 0, 0, 5]) + b"".join(
        n.to_bytes(4, "little") for n in (21, 1, 2, 3, 500)
    )
    assert decode_sid(raw) == "S-1-5-21-1-2-3-500"
    assert decode_sid("S-1-5-18") == "S-1-5-18"
    assert decode_sid(None) is None
    assert decode_sid(b"\x01") is None


def test_filetime_to_iso() -> None:
    assert filetime_to_iso(0) is None
    assert filetime_to_iso(None) is None
    assert filetime_to_iso("abc") is None
    # 2020-01-01T00:00:00Z
    assert filetime_to_iso(132223104000000000) == "2020-01-01T00:00:00+00:00"


def test_as_list_decodes_bytes() -> None:
    assert as_list(None) == []
    assert as_list([b"a", "b"]) == ["a", "b"]
    assert as_list(b"x") == ["x"]
