"""Collector DNS : accessibilite du serveur, transfert de zone (AXFR),
recursion. Ne tente jamais de mise a jour dynamique (ecriture)."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from typing import ClassVar

from adsec.collectors.base import CollectionResult, DiscoveryResult
from adsec.collectors.dns.probe import DnsProbe, build_dns_probe
from adsec.core.models.enums import AccessLevel
from adsec.core.scope.scope_manager import ScopeManager

ProbeFactory = Callable[..., DnsProbe]


class DnsCollector:
    id = "dns"
    required_access_level: ClassVar[AccessLevel] = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["dns"]

    def __init__(
        self,
        scope_manager: ScopeManager,
        port: int = 53,
        probe_factory: ProbeFactory | None = None,
    ) -> None:
        self._scope = scope_manager
        self._port = port
        self._probe_factory = probe_factory or build_dns_probe

    async def discover(self, target: str) -> DiscoveryResult:
        self._scope.assert_in_scope(target)
        return await asyncio.to_thread(self._discover_sync, target)

    async def collect(self, target: str, zone: str) -> CollectionResult:
        self._scope.assert_in_scope(target)
        return await asyncio.to_thread(self._collect_sync, target, zone)

    def _open(self, target: str) -> DnsProbe:
        return self._probe_factory(target, self._port)

    def _discover_sync(self, target: str) -> DiscoveryResult:
        probe = self._open(target)
        discovery = probe.check_reachable()
        return DiscoveryResult(
            access_level_achieved=AccessLevel.ANONYMOUS,
            facts={"reachable": discovery.reachable, "server_software": discovery.server_software},
            partial=not discovery.reachable,
            limitations=discovery.errors,
        )

    def _collect_sync(self, target: str, zone: str) -> CollectionResult:
        probe = self._open(target)
        limitations: list[str] = []

        xfr = probe.try_zone_transfer(zone)
        recursion = probe.check_recursion()
        if xfr.error:
            limitations.append(f"Transfert de zone: {xfr.error}")
        if recursion.error:
            limitations.append(f"Test de recursion: {recursion.error}")

        return CollectionResult(
            objects={
                "dns_zone_checks": [
                    {
                        "zone": zone,
                        "zone_transfer_allowed": xfr.allowed,
                        "zone_transfer_record_count": xfr.record_count,
                        "recursion_available": recursion.available,
                    }
                ]
            },
            partial=bool(limitations),
            limitations=limitations,
        )
