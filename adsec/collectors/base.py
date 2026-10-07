"""Contrat de base d'un Collector.

Un collector observe l'environnement audite en deux temps : `discover()`
identifie ce qui existe (domaine, DC, naming context...) sans encore tout
enumerer, `collect()` recupere les objets en profondeur. Cette separation
permet au moteur de decider du parallelisme et de la priorite (Discovery
avant Collection, voir `core/scheduler`).

Tout collector DOIT verifier la cible aupres du `ScopeManager` avant
d'emettre la moindre requete reseau - ce n'est pas optionnel.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol

from adsec.core.models.enums import AccessLevel


@dataclass
class DiscoveryResult:
    """Resultat de la phase de decouverte d'un collector."""

    access_level_achieved: AccessLevel
    facts: dict[str, object] = field(default_factory=dict)
    partial: bool = False
    limitations: list[str] = field(default_factory=list)


@dataclass
class CollectionResult:
    """Resultat de la phase de collecte d'un collector.

    `objects` est indexe par type d'objet (ex: "users", "groups"), chaque
    valeur etant une liste de lignes (dict) decodees, generique entre
    collectors (LDAP, SMB, DNS...).
    """

    objects: dict[str, list[dict[str, object]]] = field(default_factory=dict)
    partial: bool = False
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def count(self, kind: str) -> int:
        return len(self.objects.get(kind, []))

    def total_objects(self) -> int:
        return sum(len(v) for v in self.objects.values())


class ScanContextProtocol(Protocol):
    """Vue minimale du contexte de scan necessaire a un collector, evite
    une dependance circulaire avec `rules.base.ScanContext`."""

    engagement_id: str


class Collector(Protocol):
    id: str
    required_access_level: AccessLevel
    protocols: list[str]

    async def discover(self, target: str) -> DiscoveryResult: ...

    async def collect(self, target: str) -> CollectionResult: ...
