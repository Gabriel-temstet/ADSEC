"""Abstraction d'une sonde DNS : `DnsProbe` est le contrat utilise par le
collector, `DnspythonProbe` l'implemente par-dessus `dnspython`. Les tests
injectent une sonde factice, comme pour LDAP (`ConnectionFactory`) et SMB
(`SmbSession`).

Seules des operations en lecture sont effectuees : transfert de zone
(AXFR, une lecture volumineuse mais non destructive) et une resolution
recursive standard. Aucune mise a jour dynamique (nsupdate) n'est tentee :
il s'agirait d'une operation d'ecriture, hors du perimetre SAFE par
defaut."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class ZoneTransferResult:
    allowed: bool
    record_count: int = 0
    error: str | None = None


@dataclass
class RecursionResult:
    available: bool
    error: str | None = None


@dataclass
class DnsDiscovery:
    reachable: bool
    server_software: str | None = None
    errors: list[str] = field(default_factory=list)


class DnsProbe(Protocol):
    def check_reachable(self) -> DnsDiscovery: ...

    def try_zone_transfer(self, zone: str) -> ZoneTransferResult: ...

    def check_recursion(self, external_domain: str = "example.com") -> RecursionResult: ...


class DnspythonProbe:
    """Implementation reelle par-dessus `dnspython`."""

    def __init__(self, target: str, port: int = 53, timeout: float = 5.0) -> None:
        self._target = target
        self._port = port
        self._timeout = timeout

    def check_reachable(self) -> DnsDiscovery:
        import dns.exception
        import dns.message
        import dns.query

        try:
            query = dns.message.make_query("version.bind.", "TXT", "CH")
            response = dns.query.udp(query, self._target, port=self._port, timeout=self._timeout)
            software = None
            if response.answer:
                software = str(response.answer[0][0]).strip('"')
            return DnsDiscovery(reachable=True, server_software=software)
        except dns.exception.DNSException as exc:
            return DnsDiscovery(reachable=False, errors=[str(exc)])
        except OSError as exc:
            return DnsDiscovery(reachable=False, errors=[str(exc)])

    def try_zone_transfer(self, zone: str) -> ZoneTransferResult:
        import dns.exception
        import dns.query
        import dns.zone

        try:
            zone_data = dns.zone.from_xfr(
                dns.query.xfr(self._target, zone, port=self._port, timeout=self._timeout)
            )
            return ZoneTransferResult(allowed=True, record_count=len(zone_data.nodes))
        except (dns.exception.DNSException, ConnectionError, OSError) as exc:
            return ZoneTransferResult(allowed=False, error=str(exc))

    def check_recursion(self, external_domain: str = "example.com") -> RecursionResult:
        import dns.exception
        import dns.message
        import dns.query

        try:
            query = dns.message.make_query(external_domain, "A")
            query.flags |= 0x0100  # RD (Recursion Desired)
            response = dns.query.udp(query, self._target, port=self._port, timeout=self._timeout)
            recursion_available = bool(response.flags & 0x0080)  # RA (Recursion Available)
            return RecursionResult(available=recursion_available and bool(response.answer))
        except dns.exception.DNSException as exc:
            return RecursionResult(available=False, error=str(exc))
        except OSError as exc:
            return RecursionResult(available=False, error=str(exc))


def build_dns_probe(target: str, port: int = 53) -> DnsProbe:
    return DnspythonProbe(target, port=port)
