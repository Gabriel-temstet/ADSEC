"""Helpers partages par les controles Kerberos."""

from __future__ import annotations

from adsec.collectors.ldap.attributes import UAC_SERVER_TRUST_ACCOUNT
from adsec.rules.base import NormalizedData

AES_ENCRYPTION_BITS = 0x18  # AES128 (0x8) | AES256 (0x10)


def raw_attrs(row: dict[str, object]) -> dict[str, object]:
    value = row.get("raw_attrs")
    return value if isinstance(value, dict) else {}


def uac_of(row: dict[str, object]) -> int:
    value = raw_attrs(row).get("userAccountControl")
    return int(str(value)) if value is not None else 0


def str_list(value: object) -> list[str]:
    return [str(v) for v in value] if isinstance(value, list) else []


def is_domain_controller(row: dict[str, object]) -> bool:
    return bool(uac_of(row) & UAC_SERVER_TRUST_ACCOUNT)


def domain_controller_hosts(data: NormalizedData) -> set[str]:
    """Noms d'hote (minuscules) des DC, identifies par le flag SERVER_TRUST_ACCOUNT."""
    return {
        str(row["dns_hostname"]).lower()
        for row in data.get("computers")
        if is_domain_controller(row) and row.get("dns_hostname")
    }


def spn_host(spn: str) -> str:
    """Extrait l'hote d'un SPN 'service/host[:port][/nom]'."""
    after_service = spn.split("/", 1)[-1]
    return after_service.split("/", 1)[0].split(":", 1)[0].lower()
