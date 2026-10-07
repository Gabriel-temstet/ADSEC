"""Decodage des masques d'acces Active Directory (ACCESS_MASK) et des GUIDs
de droits etendus (extended rights) et de proprietes bien connus.

Reference : [MS-ADTS] 5.1.3.2 (ACCESS_MASK pour les objets Active
Directory) et les GUIDs d'extended rights publies par Microsoft.
"""

from __future__ import annotations

# -- ACCESS_MASK (bits generiques + specifiques Active Directory) -------

RIGHT_DELETE = 0x00010000
RIGHT_READ_CONTROL = 0x00020000
RIGHT_WRITE_DAC = 0x00040000  # WriteDACL
RIGHT_WRITE_OWNER = 0x00080000
RIGHT_GENERIC_ALL = 0x10000000
RIGHT_GENERIC_EXECUTE = 0x20000000
RIGHT_GENERIC_WRITE = 0x40000000
RIGHT_GENERIC_READ = 0x80000000
RIGHT_DS_CONTROL_ACCESS = 0x00000100  # ExtendedRight
RIGHT_DS_CREATE_CHILD = 0x00000001
RIGHT_DS_DELETE_CHILD = 0x00000002
RIGHT_DS_SELF = 0x00000008  # Validated write / Self
RIGHT_DS_READ_PROP = 0x00000010
RIGHT_DS_WRITE_PROP = 0x00000020  # WriteProperty
RIGHT_DS_DELETE_TREE = 0x00000040

_RIGHT_NAMES: tuple[tuple[int, str], ...] = (
    (RIGHT_GENERIC_ALL, "GenericAll"),
    (RIGHT_GENERIC_WRITE, "GenericWrite"),
    (RIGHT_GENERIC_READ, "GenericRead"),
    (RIGHT_GENERIC_EXECUTE, "GenericExecute"),
    (RIGHT_WRITE_DAC, "WriteDACL"),
    (RIGHT_WRITE_OWNER, "WriteOwner"),
    (RIGHT_DELETE, "Delete"),
    (RIGHT_READ_CONTROL, "ReadControl"),
    (RIGHT_DS_CONTROL_ACCESS, "ExtendedRight"),
    (RIGHT_DS_CREATE_CHILD, "CreateChild"),
    (RIGHT_DS_DELETE_CHILD, "DeleteChild"),
    (RIGHT_DS_SELF, "Self"),
    (RIGHT_DS_READ_PROP, "ReadProperty"),
    (RIGHT_DS_WRITE_PROP, "WriteProperty"),
    (RIGHT_DS_DELETE_TREE, "DeleteTree"),
)


def decode_rights(access_mask: int) -> list[str]:
    """Decompose un ACCESS_MASK en noms de droits lisibles."""
    return [name for bit, name in _RIGHT_NAMES if access_mask & bit]


def has_right(access_mask: int, *bits: int) -> bool:
    return any(access_mask & bit for bit in bits)


# -- GUIDs d'extended rights / attributs bien connus (utilises par les
# ACE de type OBJECT pour cibler un droit ou une propriete precise) ------

WELL_KNOWN_RIGHT_GUIDS: dict[str, str] = {
    "00299570-246d-11d0-a768-00aa006e0529": "ForceChangePassword",
    "ab721a53-1e2f-11d0-9819-00aa0040529b": "Self-Membership",
    "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes",
    "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2": "DS-Replication-Get-Changes-All",
    "bf9679c0-0de6-11d0-a285-00aa003049e2": "Member",  # attribut 'member'
    "f3a64788-5306-11d1-a9c5-0000f80367c1": "GPLink",  # attribut 'gPLink'
    "5f202010-79a5-11d0-9020-00c04fc2d4cf": "User-Force-Change-Password",
}


def resolve_right_guid(guid: str | None) -> str | None:
    if guid is None:
        return None
    return WELL_KNOWN_RIGHT_GUIDS.get(guid.lower())


# -- Equivalences de droits usuelles ---------------------------------------
# Dans un descripteur AD reel, les droits generiques sont generalement deja
# traduits en droits specifiques : un "Full Control" apparait donc comme
# 0x000F01FF et non comme le bit GENERIC_ALL. Les helpers ci-dessous
# couvrent les deux representations.

AD_FULL_CONTROL_MASK = 0x000F01FF
AD_GENERIC_WRITE_EQUIVALENT = RIGHT_READ_CONTROL | RIGHT_DS_WRITE_PROP | RIGHT_DS_SELF


def is_full_control(access_mask: int) -> bool:
    return (
        bool(access_mask & RIGHT_GENERIC_ALL)
        or (access_mask & AD_FULL_CONTROL_MASK) == AD_FULL_CONTROL_MASK
    )


def is_generic_write(access_mask: int, object_type_guid: str | None) -> bool:
    """GenericWrite explicite, ou droit d'ecriture sur toutes les proprietes
    (WriteProperty sans GUID cible + Self), equivalent en pratique."""
    if access_mask & RIGHT_GENERIC_WRITE:
        return True
    return (
        object_type_guid is None
        and (access_mask & AD_GENERIC_WRITE_EQUIVALENT) == AD_GENERIC_WRITE_EQUIVALENT
    )
