"""Modele de risque : Severity, Confidence, Impact, Exploitability et
Exposure restent toujours des dimensions SEPAREES - jamais fusionnees en un
score unique. `assess_risk` ne fait que lire un profil statique par
rule_id (totalement inspectable, voir `RISK_PROFILES`) et, si le finding
est correle a au moins un chemin d'attaque reel, documenter precisement
pourquoi l'impact est releve. Chaque conclusion est tracee dans
`explanation` : le pentester doit pouvoir voir exactement d'ou vient
chaque facteur, jamais une conclusion qui tombe d'une formule opaque.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, Field

from adsec.core.models.enums import Confidence, Severity
from adsec.graph.models import AttackPath


class ImpactLevel(str, Enum):
    LOCAL = "local"  # n'affecte que l'objet cible lui-meme
    LATERAL = "lateral"  # permet de controler un autre objet specifique
    DOMAIN_WIDE = "domain_wide"  # affecte potentiellement tout le domaine


class ExploitabilityLevel(str, Enum):
    TRIVIAL = "trivial"  # aucun prerequis au-dela de joindre le service
    REQUIRES_ACCESS = "requires_access"  # necessite de controler deja le principal concerne
    REQUIRES_CHAIN = "requires_chain"  # necessite plusieurs etapes/conditions prealables


# Profil de risque statique par regle : (impact de base, exploitabilite de
# base). Valeurs attribuees a la conception de chaque controle, jamais
# calculees dynamiquement - modifier ce tableau est le seul moyen de les
# changer, ce qui garde le modele entierement auditable.
RISK_PROFILES: dict[str, tuple[ImpactLevel, ExploitabilityLevel]] = {
    "AD-SEC-000": (ImpactLevel.LOCAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-ACL-001": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-ACL-002": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-ACL-003": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-ACL-004": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-ACL-005": (ImpactLevel.DOMAIN_WIDE, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-TRUST-001": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_CHAIN),
    "AD-KRB-001": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
    "AD-KRB-002": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
    "AD-KRB-003": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_CHAIN),
    "AD-KRB-004": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_CHAIN),
    "AD-KRB-005": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_CHAIN),
    "AD-KRB-006": (ImpactLevel.LOCAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-GPO-001": (ImpactLevel.LATERAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-GPO-002": (ImpactLevel.LOCAL, ExploitabilityLevel.REQUIRES_ACCESS),
    "AD-SMB-001": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
    "AD-SMB-002": (ImpactLevel.LOCAL, ExploitabilityLevel.REQUIRES_CHAIN),
    "AD-SMB-003": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
    "AD-SMB-004": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
    "AD-DNS-001": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
    "AD-DNS-002": (ImpactLevel.LOCAL, ExploitabilityLevel.TRIVIAL),
}

_DEFAULT_PROFILE = (ImpactLevel.LOCAL, ExploitabilityLevel.REQUIRES_ACCESS)


class RiskAssessment(BaseModel):
    rule_id: str
    severity: Severity
    confidence: Confidence
    impact: ImpactLevel
    exploitability: ExploitabilityLevel
    exposure: int = 0  # nombre de chemins d'attaque reels correles
    reachable_targets: list[str] = Field(default_factory=list)
    explanation: list[str] = Field(default_factory=list)


def assess_risk(
    rule_id: str,
    severity: Severity,
    confidence: Confidence,
    linked_paths: list[AttackPath],
) -> RiskAssessment:
    base_impact, base_exploitability = RISK_PROFILES.get(rule_id, _DEFAULT_PROFILE)
    explanation = [
        f"Impact de base pour {rule_id} : {base_impact.value} (profil de regle statique).",
        (
            f"Exploitabilite de base pour {rule_id} : {base_exploitability.value} "
            "(profil de regle statique)."
        ),
    ]

    impact = base_impact
    reachable_targets = sorted({p.target_id for p in linked_paths})

    if linked_paths:
        if impact != ImpactLevel.DOMAIN_WIDE:
            impact = ImpactLevel.DOMAIN_WIDE
            explanation.append(
                f"Impact releve de {base_impact.value} a domain_wide : "
                f"{len(linked_paths)} chemin(s) d'attaque confirme(s) (profil 'deep') "
                f"vers {', '.join(reachable_targets)}."
            )
        else:
            explanation.append(
                f"Impact confirme par {len(linked_paths)} chemin(s) d'attaque vers "
                f"{', '.join(reachable_targets)}."
            )
    else:
        explanation.append(
            "Aucun chemin d'attaque correle vers un actif critique (necessite un scan "
            "en profil 'deep' pour le calcul des chemins)."
        )

    return RiskAssessment(
        rule_id=rule_id,
        severity=severity,
        confidence=confidence,
        impact=impact,
        exploitability=base_exploitability,
        exposure=len(linked_paths),
        reachable_targets=reachable_targets,
        explanation=explanation,
    )
