"""Fonctions de correspondance pour le scope (glob host, CIDR, domaine)."""

from __future__ import annotations

import ipaddress
from fnmatch import fnmatch


def host_matches(pattern: str, host: str) -> bool:
    """Compare un hostname/FQDN a un pattern glob (ex: '*.example.local')."""
    return fnmatch(host.lower().rstrip("."), pattern.lower().rstrip("."))


def domain_matches(domain_pattern: str, host: str) -> bool:
    """Verifie qu'un host appartient a un domaine (ou est le domaine lui-meme)."""
    host = host.lower().rstrip(".")
    domain_pattern = domain_pattern.lower().rstrip(".")
    return host == domain_pattern or host.endswith("." + domain_pattern)


def ip_in_network(ip_str: str, network_str: str) -> bool:
    """Verifie qu'une IP appartient a un reseau CIDR. Retourne False si l'IP
    fournie n'est pas une IP valide (ex: un hostname)."""
    try:
        ip = ipaddress.ip_address(ip_str)
        network = ipaddress.ip_network(network_str, strict=False)
    except ValueError:
        return False
    return ip in network


def is_ip_literal(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False
