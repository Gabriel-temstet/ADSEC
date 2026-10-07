"""AD-TRUST-001 : trust externe sortant sans filtrage SID detecte."""

from __future__ import annotations

from typing import ClassVar

from adsec.core.models.enums import AccessLevel, Confidence, Severity
from adsec.rules.base import (
    CheckPlugin,
    DataRequirement,
    EvidenceRef,
    Finding,
    NormalizedData,
    ScanContext,
)

_TRUST_ATTR_FOREST_TRANSITIVE = 0x8
_TRUST_ATTR_WITHIN_FOREST = 0x20


class ExternalTrustWithoutSidFiltering(CheckPlugin):
    id = "AD-TRUST-001"
    name = "Trust externe sans filtrage SID detecte"
    version = "1.0.0"
    category = "trusts"
    description = (
        "Detecte les trusts externes (hors foret, hors trust de foret) ou nous "
        "faisons confiance a un domaine partenaire, sans attribut de filtrage SID."
    )
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [DataRequirement(kind="trusts", description="Trusts du domaine")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings: list[Finding] = []
        for trust in data.get("trusts"):
            raw = trust.get("raw_attrs") or {}
            attrs = int(str(raw.get("trustAttributes", 0))) if isinstance(raw, dict) else 0
            partner = str(trust["trust_partner"])

            if attrs & (_TRUST_ATTR_WITHIN_FOREST | _TRUST_ATTR_FOREST_TRANSITIVE):
                continue  # trust intra-foret ou de foret : filtrage gere differemment
            if trust.get("direction") not in ("outbound", "bidirectional"):
                continue  # nous ne faisons pas confiance a ce partenaire
            if trust.get("sid_filtering"):
                continue

            findings.append(
                Finding(
                    rule_id=self.id,
                    title=f"Trust externe sans filtrage SID detecte vers {partner}",
                    category=self.category,
                    severity=Severity.MEDIUM,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Le domaine fait confiance a {partner} (trust externe, direction "
                        f"{trust.get('direction')}) et l'attribut de filtrage SID n'est pas "
                        "positionne dans trustAttributes."
                    ),
                    technical_details=(
                        f"Pourquoi detecte : trustAttributes=0x{attrs:X} ne contient pas le "
                        "bit de filtrage SID (0x4). Pourquoi risque : sans filtrage, un SID "
                        "privilegie injecte dans le SID history d'un compte du domaine "
                        "partenaire peut etre honore ici. Faux positif possible : le "
                        "filtrage peut etre applique par un mecanisme non visible via cet "
                        "attribut ; niveau de confiance limite a MEDIUM pour cette raison."
                    ),
                    impact=(
                        "Un domaine partenaire compromis pourrait servir de point d'entree "
                        "vers des privileges eleves dans ce domaine."
                    ),
                    validation_procedure=(
                        f"Verifier l'etat du filtrage SID du trust vers {partner} "
                        "(netdom trust <domaine> /domain:<partenaire> /quarantine ou "
                        "Get-ADTrust). Aucune action sur le trust n'est necessaire."
                    ),
                    remediation=(
                        f"Activer la quarantaine/le filtrage SID sur le trust vers {partner} "
                        "ou supprimer le trust s'il n'est plus necessaire."
                    ),
                    affected_assets=[partner],
                    principal=partner,
                    condition_key="no-sid-filtering",
                    evidence=[
                        EvidenceRef(
                            source="ldap",
                            object_type="trust",
                            object_id=partner,
                            attribute="trustAttributes",
                            value=f"0x{attrs:X}",
                        )
                    ],
                    references=[
                        "https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc772633(v=ws.10)",
                    ],
                    mitre_technique_id=None,
                )
            )
        return findings
