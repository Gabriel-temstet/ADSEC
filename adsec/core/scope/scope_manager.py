"""ScopeManager : fonctionnalite de securite centrale d'ADSEC.

Toute operation reseau du moteur (collectors, plugins) DOIT appeler
`assert_in_scope()` avant d'emettre la moindre requete vers une cible.
Un manquement a cette regle est considere comme une violation de securite
du produit lui-meme, pas seulement de la mission.
"""

from __future__ import annotations

from dataclasses import dataclass

from adsec.core.models.engagement import Scope
from adsec.core.scope.matcher import domain_matches, host_matches, ip_in_network, is_ip_literal


class OutOfScopeError(Exception):
    """Levee lorsqu'une operation cible un element hors du scope de mission."""

    def __init__(self, target: str, reason: str) -> None:
        self.target = target
        self.reason = reason
        super().__init__(f"Cible hors scope refusee: {target!r} ({reason})")


@dataclass
class ScopeDecision:
    target: str
    in_scope: bool
    reason: str


class ScopeManager:
    """Evalue si une cible (hostname, FQDN ou IP) appartient au scope autorise.

    Regle de priorite : une exclusion explicite (host ou reseau) l'emporte
    toujours sur une inclusion, meme plus specifique.
    """

    def __init__(self, scope: Scope) -> None:
        self._scope = scope

    @property
    def scope(self) -> Scope:
        return self._scope

    def evaluate(self, target: str) -> ScopeDecision:
        target = target.strip()
        if not target:
            return ScopeDecision(target, False, "cible vide")

        if self._is_excluded(target):
            return ScopeDecision(target, False, "exclusion explicite du scope")

        if self._is_included(target):
            return ScopeDecision(target, True, "correspond a une regle d'inclusion")

        return ScopeDecision(target, False, "aucune regle d'inclusion ne correspond")

    def is_in_scope(self, target: str) -> bool:
        return self.evaluate(target).in_scope

    def assert_in_scope(self, target: str) -> None:
        """Point de controle obligatoire avant toute I/O reseau.

        Leve `OutOfScopeError` si la cible n'est pas explicitement autorisee.
        Cette methode ne doit jamais etre contournee par un collector ou un
        plugin, y compris en mode 'deep'.
        """
        decision = self.evaluate(target)
        if not decision.in_scope:
            raise OutOfScopeError(target, decision.reason)

    def intrusive_allowed(self) -> bool:
        return self._scope.intrusive_actions_enabled

    def assert_intrusive_allowed(self, action_name: str) -> None:
        if not self.intrusive_allowed():
            raise OutOfScopeError(
                action_name,
                "action intrusive non autorisee (intrusive_actions_enabled=false)",
            )

    # -- internes -----------------------------------------------------

    def _is_excluded(self, target: str) -> bool:
        for pattern in self._scope.hosts_exclude:
            if host_matches(pattern, target):
                return True
        if is_ip_literal(target):
            for network in self._scope.networks_exclude:
                if ip_in_network(target, network):
                    return True
        return False

    def _is_included(self, target: str) -> bool:
        for domain in self._scope.domains:
            if domain_matches(domain, target):
                return True
        for pattern in self._scope.hosts_include:
            if host_matches(pattern, target):
                return True
        if is_ip_literal(target):
            for network in self._scope.networks_include:
                if ip_in_network(target, network):
                    return True
        return False
