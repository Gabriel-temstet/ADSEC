"""Decodage des attributs LDAP/Active Directory bruts vers des types
Python exploitables par le reste du moteur (SID, userAccountControl,
timestamps Windows FILETIME, DN -> RDN, naming context -> FQDN)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

# -- userAccountControl (bitmask) --------------------------------------

UAC_ACCOUNTDISABLE = 0x0002
UAC_DONT_EXPIRE_PASSWD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000  # unconstrained delegation
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_SERVER_TRUST_ACCOUNT = 0x2000  # controleur de domaine
UAC_NOT_DELEGATED = 0x100000  # compte sensible, ne peut pas etre delegue
UAC_USE_DES_KEY_ONLY = 0x200000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000  # protocol transition

_FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=UTC)


def uac_has_flag(uac: int | None, flag: int) -> bool:
    if uac is None:
        return False
    return bool(uac & flag)


def is_account_enabled(uac: int | None) -> bool:
    if uac is None:
        return True
    return not uac_has_flag(uac, UAC_ACCOUNTDISABLE)


def naming_context_to_fqdn(naming_context: str) -> str:
    """Convertit 'DC=corp,DC=example' en 'corp.example'."""
    parts = []
    for component in naming_context.split(","):
        component = component.strip()
        if component.upper().startswith("DC="):
            parts.append(component[3:])
    return ".".join(parts)


def rdn_and_parent(dn: str) -> tuple[str, str | None]:
    """Extrait le nom (valeur du premier RDN) et le DN parent."""
    parts = [p.strip() for p in dn.split(",")]
    if not parts:
        return dn, None
    first = parts[0]
    name = first.split("=", 1)[1] if "=" in first else first
    parent = ",".join(parts[1:]) if len(parts) > 1 else None
    return name, parent


def filetime_to_iso(value: object) -> str | None:
    """Convertit un timestamp Windows FILETIME (100ns depuis 1601) en ISO 8601.

    Retourne None pour les valeurs sentinelles (0, absente, ou deja un
    datetime fourni par ldap3 pour les attributs GeneralizedTime)."""
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.astimezone(UTC).isoformat()
    if not isinstance(value, int | str | bytes | bytearray):
        return None
    try:
        raw = int(value)
    except ValueError:
        return None
    if raw <= 0:
        return None
    try:
        dt = _FILETIME_EPOCH + timedelta(microseconds=raw / 10)
    except OverflowError:
        return None
    return dt.isoformat()


def decode_sid(raw: object) -> str | None:
    """Decode un SID binaire Active Directory (format SDDL S-1-...).

    ldap3 renvoie generalement `objectSid` sous forme de bytes bruts pour
    les attributs binaires non reconnus par son schema.
    """
    if raw is None:
        return None
    if isinstance(raw, str) and raw.startswith("S-1-"):
        return raw
    if not isinstance(raw, bytes | bytearray):
        return None
    data = bytes(raw)
    if len(data) < 8:
        return None
    revision = data[0]
    sub_authority_count = data[1]
    identifier_authority = int.from_bytes(data[2:8], byteorder="big")
    sub_authorities = []
    offset = 8
    for _ in range(sub_authority_count):
        if offset + 4 > len(data):
            break
        sub_authorities.append(int.from_bytes(data[offset : offset + 4], byteorder="little"))
        offset += 4
    parts = [str(revision), str(identifier_authority), *[str(s) for s in sub_authorities]]
    return "S-" + "-".join(parts)


def _decode_text(value: object) -> str:
    if isinstance(value, bytes | bytearray):
        return bytes(value).decode("utf-8", errors="replace")
    return str(value)


def as_list(value: object) -> list[str]:
    """Normalise un attribut LDAP multi-valeur (texte, ou absent) en liste
    de str, en decodant les valeurs brutes en bytes (utf-8)."""
    if value is None:
        return []
    if isinstance(value, list):
        return [_decode_text(v) for v in value]
    return [_decode_text(value)]


@dataclass(frozen=True)
class GpLink:
    """Un lien de GPO decode depuis l'attribut `gPLink`."""

    guid: str
    options: int

    @property
    def disabled(self) -> bool:
        return bool(self.options & 0x1)

    @property
    def enforced(self) -> bool:
        return bool(self.options & 0x2)


_GPLINK_RE = re.compile(r"\[LDAP://[^;\]]*?\{([0-9A-Fa-f-]{36})\}[^;\]]*;(\d+)\]", re.IGNORECASE)


def parse_gplink(value: str | None) -> list[GpLink]:
    """Decode un attribut gPLink ('[LDAP://cn={GUID},cn=policies,...;0][...]')."""
    if not value:
        return []
    return [
        GpLink(guid=m.group(1).upper(), options=int(m.group(2))) for m in _GPLINK_RE.finditer(value)
    ]


def guid_from_dn(dn: str) -> str | None:
    """Extrait le GUID '{...}' du premier RDN d'un DN de GPO."""
    match = re.match(r"(?i)^cn=\{([0-9A-Fa-f-]{36})\}", dn.strip())
    return match.group(1).upper() if match else None
