"""Parseur du security descriptor binaire Windows (format self-relative)
tel que renvoye par l'attribut LDAP `nTSecurityDescriptor`.

Reference du format : [MS-DTYP] 2.4.6 SECURITY_DESCRIPTOR,
2.4.5 ACL, 2.4.4 ACE. Seules les ACE de type ACCESS_ALLOWED,
ACCESS_DENIED et leurs variantes OBJECT (utilisees par AD pour les
extended rights / write-property cibles) sont decodees ; les autres types
sont ignores silencieusement (SACL notamment, non pertinent pour l'audit
de permissions).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from uuid import UUID

# -- Types d'ACE ---------------------------------------------------------

ACE_TYPE_ACCESS_ALLOWED = 0x00
ACE_TYPE_ACCESS_DENIED = 0x01
ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
ACE_TYPE_ACCESS_DENIED_OBJECT = 0x06

_ACE_TYPE_NAMES = {
    ACE_TYPE_ACCESS_ALLOWED: "ALLOWED",
    ACE_TYPE_ACCESS_DENIED: "DENIED",
    ACE_TYPE_ACCESS_ALLOWED_OBJECT: "ALLOWED_OBJECT",
    ACE_TYPE_ACCESS_DENIED_OBJECT: "DENIED_OBJECT",
}

_SUPPORTED_ACE_TYPES = frozenset(_ACE_TYPE_NAMES)

# Bit ACE_OBJECT_TYPE_PRESENT / ACE_INHERITED_OBJECT_TYPE_PRESENT (ObjectAce flags)
_ACE_OBJECT_TYPE_PRESENT = 0x1
_ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x2

# Bit AceFlags: INHERITED_ACE
_ACE_FLAG_INHERITED = 0x10

# Control flag SE_DACL_PRESENT dans SECURITY_DESCRIPTOR.Control
_SE_DACL_PRESENT = 0x0004


@dataclass(frozen=True)
class Ace:
    ace_type: str
    trustee_sid: str
    access_mask: int
    inherited: bool
    object_type_guid: str | None = None


@dataclass
class SecurityDescriptor:
    owner_sid: str | None = None
    group_sid: str | None = None
    dacl_present: bool = False
    aces: list[Ace] = field(default_factory=list)


class SecurityDescriptorParseError(Exception):
    pass


def _decode_sid(data: bytes, offset: int) -> tuple[str, int]:
    """Decode un SID binaire a `offset`. Retourne (sid, taille_en_octets)."""
    if offset + 8 > len(data):
        raise SecurityDescriptorParseError("SID tronque")
    revision = data[offset]
    sub_authority_count = data[offset + 1]
    identifier_authority = int.from_bytes(data[offset + 2 : offset + 8], byteorder="big")
    size = 8 + 4 * sub_authority_count
    if offset + size > len(data):
        raise SecurityDescriptorParseError("SID tronque (sous-autorites)")
    sub_authorities = [
        int.from_bytes(data[offset + 8 + 4 * i : offset + 12 + 4 * i], byteorder="little")
        for i in range(sub_authority_count)
    ]
    parts = [str(revision), str(identifier_authority), *[str(s) for s in sub_authorities]]
    return "S-" + "-".join(parts), size


def _decode_guid(data: bytes, offset: int) -> str:
    """Decode un GUID Windows (little-endian mixe) de 16 octets en chaine."""
    raw = data[offset : offset + 16]
    if len(raw) != 16:
        raise SecurityDescriptorParseError("GUID tronque")
    return str(UUID(bytes_le=raw))


def _parse_acl(data: bytes, acl_offset: int) -> list[Ace]:
    if acl_offset == 0 or acl_offset + 8 > len(data):
        return []
    ace_count = struct.unpack_from("<H", data, acl_offset + 4)[0]
    aces: list[Ace] = []
    pos = acl_offset + 8  # apres ACL_HEADER (AclRevision, Sbz1, AclSize, AceCount, Sbz2)

    for _ in range(ace_count):
        if pos + 4 > len(data):
            break
        ace_type = data[pos]
        ace_flags = data[pos + 1]
        ace_size = struct.unpack_from("<H", data, pos + 2)[0]
        if ace_size == 0 or pos + ace_size > len(data):
            break

        if ace_type in _SUPPORTED_ACE_TYPES:
            body = pos + 4
            access_mask = struct.unpack_from("<I", data, body)[0]
            cursor = body + 4
            object_type_guid = None

            if ace_type in (ACE_TYPE_ACCESS_ALLOWED_OBJECT, ACE_TYPE_ACCESS_DENIED_OBJECT):
                object_flags = struct.unpack_from("<I", data, cursor)[0]
                cursor += 4
                if object_flags & _ACE_OBJECT_TYPE_PRESENT:
                    object_type_guid = _decode_guid(data, cursor)
                    cursor += 16
                if object_flags & _ACE_INHERITED_OBJECT_TYPE_PRESENT:
                    cursor += 16  # InheritedObjectType, non utilise ici

            trustee_sid, _ = _decode_sid(data, cursor)
            aces.append(
                Ace(
                    ace_type=_ACE_TYPE_NAMES[ace_type],
                    trustee_sid=trustee_sid,
                    access_mask=access_mask,
                    inherited=bool(ace_flags & _ACE_FLAG_INHERITED),
                    object_type_guid=object_type_guid,
                )
            )

        pos += ace_size

    return aces


def parse_security_descriptor(raw: object) -> SecurityDescriptor | None:
    """Parse un `nTSecurityDescriptor` binaire brut. Retourne None si la
    valeur est absente ou manifestement invalide (ne leve jamais pour une
    entree malformee isolee : un objet illisible ne doit pas interrompre
    la collecte des autres)."""
    if raw is None:
        return None
    if not isinstance(raw, bytes | bytearray):
        return None
    data = bytes(raw)
    if len(data) < 20:
        return None

    try:
        control = struct.unpack_from("<H", data, 2)[0]
        owner_offset = struct.unpack_from("<I", data, 4)[0]
        group_offset = struct.unpack_from("<I", data, 8)[0]
        dacl_offset = struct.unpack_from("<I", data, 16)[0]

        owner_sid = _decode_sid(data, owner_offset)[0] if owner_offset else None
        group_sid = _decode_sid(data, group_offset)[0] if group_offset else None
        dacl_present = bool(control & _SE_DACL_PRESENT)
        aces = _parse_acl(data, dacl_offset) if dacl_present else []

        return SecurityDescriptor(
            owner_sid=owner_sid, group_sid=group_sid, dacl_present=dacl_present, aces=aces
        )
    except (SecurityDescriptorParseError, struct.error):
        return None
