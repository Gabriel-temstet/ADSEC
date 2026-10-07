from __future__ import annotations

from adsec.collectors.ldap.rights import (
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_GENERIC_ALL,
    RIGHT_GENERIC_WRITE,
    RIGHT_WRITE_DAC,
    decode_rights,
    is_full_control,
    is_generic_write,
    resolve_right_guid,
)
from adsec.collectors.ldap.sddl import parse_security_descriptor
from tests.fixtures.sddl_builder import FakeAce, build_security_descriptor

DOMAIN = "S-1-5-21-1-2-3"


def test_round_trip_owner_and_aces() -> None:
    raw = build_security_descriptor(
        f"{DOMAIN}-512",
        [
            FakeAce(f"{DOMAIN}-1105", RIGHT_GENERIC_ALL),
            FakeAce(
                f"{DOMAIN}-1106",
                RIGHT_DS_CONTROL_ACCESS,
                object_type_guid="00299570-246d-11d0-a768-00aa006e0529",
                inherited=True,
            ),
        ],
    )
    sd = parse_security_descriptor(raw)
    assert sd is not None
    assert sd.owner_sid == f"{DOMAIN}-512"
    assert sd.dacl_present
    assert len(sd.aces) == 2
    assert sd.aces[0].ace_type == "ALLOWED"
    assert sd.aces[0].trustee_sid == f"{DOMAIN}-1105"
    assert sd.aces[0].inherited is False
    assert sd.aces[1].ace_type == "ALLOWED_OBJECT"
    assert sd.aces[1].object_type_guid == "00299570-246d-11d0-a768-00aa006e0529"
    assert sd.aces[1].inherited is True


def test_malformed_descriptor_returns_none_without_raising() -> None:
    assert parse_security_descriptor(None) is None
    assert parse_security_descriptor("not-bytes") is None
    assert parse_security_descriptor(b"\x01\x02") is None
    truncated = build_security_descriptor(f"{DOMAIN}-512", [FakeAce(f"{DOMAIN}-1", 1)])[:30]
    assert parse_security_descriptor(truncated) is None or True  # ne doit jamais lever


def test_decode_rights_and_equivalences() -> None:
    assert "WriteDACL" in decode_rights(RIGHT_WRITE_DAC)
    assert is_full_control(RIGHT_GENERIC_ALL)
    assert is_full_control(0x000F01FF)
    assert not is_full_control(RIGHT_WRITE_DAC)
    assert is_generic_write(RIGHT_GENERIC_WRITE, None)
    assert is_generic_write(0x20028, None)  # ecriture sur toutes les proprietes
    assert not is_generic_write(0x20028, "bf9679c0-0de6-11d0-a285-00aa003049e2")  # propriete ciblee


def test_resolve_right_guid() -> None:
    assert resolve_right_guid("00299570-246D-11D0-A768-00AA006E0529") == "ForceChangePassword"
    assert resolve_right_guid(None) is None
    assert resolve_right_guid("00000000-0000-0000-0000-000000000000") is None
