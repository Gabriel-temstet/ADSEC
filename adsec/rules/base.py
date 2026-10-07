"""Contrat de base d'un plugin de controle ADSEC (`CheckPlugin`).

Un plugin declare ses metadonnees en attributs de classe, ses besoins en
donnees via `requires()`, et produit des `Finding` via `run()`. Aucun
plugin ne modifie l'environnement audite : les plugins marques
`intrusive=True` sont exclus par defaut du moteur (voir PluginManager).
"""

from __future__ import annotations

import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import ClassVar

from adsec.core.models.enums import AccessLevel, Confidence, FindingStatus, Severity


@dataclass(frozen=True)
class DataRequirement:
    """Decrit une donnee necessaire a l'execution d'un plugin.

    `kind` est une cle libre mais conventionnelle (ex: "users", "acl",
    "gpo") resolue par le moteur pour determiner l'ordre d'execution en
    fonction des collectors/analyzers deja executes.
    """

    kind: str
    description: str = ""


@dataclass
class EvidenceRef:
    source: str
    object_type: str
    object_id: str
    attribute: str
    value: str


@dataclass
class Finding:
    """Format standardise d'un finding produit par un plugin."""

    rule_id: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    description: str
    technical_details: str
    impact: str
    validation_procedure: str
    remediation: str
    affected_assets: list[str] = field(default_factory=list)
    evidence: list[EvidenceRef] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    mitre_technique_id: str | None = None
    principal: str = ""
    condition_key: str = ""
    status: FindingStatus = FindingStatus.OPEN
    first_seen: datetime = field(default_factory=lambda: datetime.now(UTC))

    def fingerprint(self, principal: str | None = None, condition_key: str | None = None) -> str:
        """Cle de deduplication : rule_id + object_id(s) + principal + condition.

        Deux plugins differents detectant le meme probleme sur le meme objet
        avec le meme principal doivent produire la meme empreinte. Les
        arguments, s'ils sont fournis, l'emportent sur les champs `principal`
        et `condition_key` du finding.
        """
        principal = self.principal if principal is None else principal
        condition_key = self.condition_key if condition_key is None else condition_key
        assets_key = ",".join(sorted(self.affected_assets))
        raw = f"{self.rule_id}|{assets_key}|{principal}|{condition_key}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


@dataclass
class NormalizedData:
    """Vue normalisee des donnees collectees, passee aux plugins.

    En Phase 2, seule la configuration/le scope sont disponibles ; les
    donnees AD (users/groups/ACL/...) seront alimentees a partir de la
    Phase 3 par les collectors, sans changer ce contrat.
    """

    engagement_id: str
    tables: dict[str, list[dict[str, object]]] = field(default_factory=dict)

    def get(self, kind: str) -> list[dict[str, object]]:
        return self.tables.get(kind, [])


@dataclass
class ScanContext:
    """Contexte d'execution transmis a chaque plugin."""

    engagement_id: str
    scan_job_id: str
    access_level: AccessLevel
    profile: str


class CheckPlugin(ABC):
    """Classe de base que tout plugin de controle doit heriter.

    Attributs obligatoires a definir dans chaque sous-classe :
    id, name, version, category, description, severity_hint,
    required_permissions, protocols, intrusive.
    """

    id: ClassVar[str]
    name: ClassVar[str]
    version: ClassVar[str]
    category: ClassVar[str]
    description: ClassVar[str]
    severity_hint: ClassVar[Severity]
    required_permissions: ClassVar[AccessLevel]
    protocols: ClassVar[list[str]]
    intrusive: ClassVar[bool] = False

    def __init_subclass__(cls, **kwargs: object) -> None:
        super().__init_subclass__(**kwargs)
        required_attrs = (
            "id",
            "name",
            "version",
            "category",
            "description",
            "severity_hint",
            "required_permissions",
            "protocols",
        )
        missing = [attr for attr in required_attrs if not hasattr(cls, attr)]
        if missing:
            raise TypeError(
                f"Le plugin {cls.__name__} n'implemente pas les attributs "
                f"obligatoires: {', '.join(missing)}"
            )

    @abstractmethod
    def requires(self) -> list[DataRequirement]:
        """Retourne les donnees necessaires a l'execution du plugin."""
        raise NotImplementedError

    @abstractmethod
    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        """Execute le controle et retourne zero ou plusieurs findings."""
        raise NotImplementedError

    def is_compatible_with_access(self, access_level: AccessLevel) -> bool:
        order = [
            AccessLevel.ANONYMOUS,
            AccessLevel.AUTHENTICATED,
            AccessLevel.AUDITOR,
            AccessLevel.PRIVILEGED,
        ]
        return order.index(access_level) >= order.index(self.required_permissions)
