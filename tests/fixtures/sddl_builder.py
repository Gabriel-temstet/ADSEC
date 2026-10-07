"""Constructeur de security descriptors binaires (format self-relative),
utilise uniquement pour fabriquer des donnees de test realistes. Le
produit ne fait qu'analyser des security descriptors (voir
`adsec.collectors.ldap.sddl`) ; il n'en construit jamais.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from uuid import UUID

_SE_DACL_PRESENT = 0x0004
_SE_SELF_RELATIVE = 0x8000
_ACE_TYPE_ACCESS_ALLOWED = 0x00
_ACE_TYPE_ACCESS_ALLOWED_OBJECT = 0x05
_ACE_OBJECT_TYPE_PRESENT = 0x1


@dataclass(frozen=True)
class FakeAce:
    trustee_sid: str
    access_mask: int
    object_type_guid: str | None = None
    inherited: bool = False


def encode_sid(sid: str) -> bytes:
    parts = sid.split("-")
    revision = int(parts[1])
    identifier_authority = int(parts[2])
    sub_authorities = [int(p) for p in parts[3:]]
    out = bytes([revision, len(sub_authorities)]) + identifier_authority.to_bytes(6, "big")
    for sub in sub_authorities:
        out += sub.to_bytes(4, "little")
    return out


def _encode_ace(ace: FakeAce) -> bytes:
    sid_bytes = encode_sid(ace.trustee_sid)
    ace_flags = 0x10 if ace.inherited else 0x00

    if ace.object_type_guid is not None:
        object_flags = _ACE_OBJECT_TYPE_PRESENT
        guid_bytes = UUID(ace.object_type_guid).bytes_le
        body = (
            struct.pack("<I", ace.access_mask)
            + struct.pack("<I", object_flags)
            + guid_bytes
            + sid_bytes
        )
        ace_type = _ACE_TYPE_ACCESS_ALLOWED_OBJECT
    else:
        body = struct.pack("<I", ace.access_mask) + sid_bytes
        ace_type = _ACE_TYPE_ACCESS_ALLOWED

    ace_size = 4 + len(body)
    return struct.pack("<BBH", ace_type, ace_flags, ace_size) + body


def build_security_descriptor(owner_sid: str, aces: list[FakeAce]) -> bytes:
    """Construit un SECURITY_DESCRIPTOR self-relative minimal : owner + DACL."""
    ace_blobs = [_encode_ace(a) for a in aces]
    acl_body = b"".join(ace_blobs)
    acl_header = struct.pack("<BBHHH", 2, 0, 8 + len(acl_body), len(aces), 0)
    dacl = acl_header + acl_body

    owner_sid_bytes = encode_sid(owner_sid)

    header_size = 20
    owner_offset = header_size
    dacl_offset = owner_offset + len(owner_sid_bytes)

    control = _SE_DACL_PRESENT | _SE_SELF_RELATIVE
    header = struct.pack(
        "<BBHIIII",
        1,  # Revision
        0,  # Sbz1
        control,
        owner_offset,
        0,  # group_offset (non renseigne dans ce fixture minimal)
        0,  # sacl_offset
        dacl_offset,
    )
    return header + owner_sid_bytes + dacl
