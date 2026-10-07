"""Sonde DNS factice pour les tests : implemente `DnsProbe` sans reseau,
avec un scenario representatif (serveur joignable, transfert de zone
autorise, recursion ouverte)."""

from __future__ import annotations

from adsec.collectors.dns.probe import DnsDiscovery, RecursionResult, ZoneTransferResult


class FakeDnsProbe:
    def __init__(
        self,
        reachable: bool = True,
        zone_transfer_allowed: bool = True,
        record_count: int = 37,
        recursion_available: bool = True,
    ) -> None:
        self._reachable = reachable
        self._zone_transfer_allowed = zone_transfer_allowed
        self._record_count = record_count
        self._recursion_available = recursion_available

    def check_reachable(self) -> DnsDiscovery:
        if not self._reachable:
            return DnsDiscovery(reachable=False, errors=["timeout"])
        return DnsDiscovery(reachable=True, server_software="Microsoft DNS 10.0")

    def try_zone_transfer(self, zone: str) -> ZoneTransferResult:
        if not self._zone_transfer_allowed:
            return ZoneTransferResult(allowed=False, error="transfer refused")
        return ZoneTransferResult(allowed=True, record_count=self._record_count)

    def check_recursion(self, external_domain: str = "example.com") -> RecursionResult:
        return RecursionResult(available=self._recursion_available)


def build_fake_dns_probe(target: str, port: int) -> FakeDnsProbe:
    return FakeDnsProbe()


def build_hardened_dns_probe(target: str, port: int) -> FakeDnsProbe:
    return FakeDnsProbe(zone_transfer_allowed=False, recursion_available=False)
