"""Controles DNS : transfert de zone, recursion ouverte."""

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
from adsec.rules.factory import new_finding

_MS_DNS_DOC = "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-zone-transfer-fails"


class ZoneTransferAllowed(CheckPlugin):
    id = "AD-DNS-001"
    name = "Transfert de zone DNS autorise"
    version = "1.0.0"
    category = "dns"
    description = "Detecte les zones DNS acceptant un transfert de zone (AXFR) non restreint."
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["dns"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [DataRequirement(kind="dns_zone_checks")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for check in data.get("dns_zone_checks"):
            if not check.get("zone_transfer_allowed"):
                continue
            zone = str(check["zone"])
            count = check.get("zone_transfer_record_count", 0)
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Transfert de zone autorise pour {zone}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Le serveur DNS a accepte un transfert de zone (AXFR) complet pour "
                        f"{zone} ({count} enregistrements recuperes)."
                    ),
                    why_detected="La requete AXFR a reussi et a retourne le contenu de la zone.",
                    why_risky=(
                        "Un transfert de zone expose la cartographie complete des noms internes "
                        "(hotes, services, parfois des noms revelateurs d'infrastructure sensible) "
                        "a n'importe quel client pouvant joindre le serveur DNS."
                    ),
                    false_positive=(
                        "Le transfert peut n'etre accessible que depuis un reseau interne "
                        "restreint ; le risque depend de qui peut atteindre ce serveur DNS."
                    ),
                    impact="Reconnaissance facilitee de l'infrastructure interne.",
                    validation=f"Reproduire avec 'dig axfr {zone} @<serveur>' depuis differents emplacements reseau.",
                    remediation=(
                        f"Restreindre les transferts de zone de {zone} aux seuls serveurs DNS "
                        "secondaires legitimes (onglet Transferts de zone du serveur DNS)."
                    ),
                    assets=[zone],
                    principal=zone,
                    condition_key="zone-transfer-allowed",
                    evidence=[
                        EvidenceRef(
                            source="dns",
                            object_type="zone",
                            object_id=zone,
                            attribute="zone_transfer_allowed",
                            value=f"True ({count} enregistrements)",
                        )
                    ],
                    references=[_MS_DNS_DOC],
                    mitre_technique_id="T1590.002",
                )
            )
        return findings


class OpenRecursion(CheckPlugin):
    id = "AD-DNS-002"
    name = "Recursion DNS ouverte"
    version = "1.0.0"
    category = "dns"
    description = (
        "Detecte un serveur DNS repondant a des requetes recursives pour des domaines externes."
    )
    severity_hint = Severity.LOW
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["dns"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [DataRequirement(kind="dns_zone_checks")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for check in data.get("dns_zone_checks"):
            if not check.get("recursion_available"):
                continue
            zone = str(check["zone"])
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Recursion DNS ouverte sur le serveur de {zone}",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=(
                        "Le serveur DNS a resolu un nom de domaine externe pour ce client, "
                        "indiquant que la recursion n'est pas restreinte a un perimetre interne."
                    ),
                    why_detected="Une requete recursive pour un domaine externe a retourne une reponse resolue.",
                    why_risky=(
                        "Un serveur DNS interne accessible depuis l'exterieur et acceptant la "
                        "recursion peut etre utilise pour de l'amplification DDoS ou du cache "
                        "poisoning ; en interne, c'est surtout un signe d'absence de "
                        "segmentation du service DNS."
                    ),
                    false_positive=(
                        "Comportement normal si ce serveur DNS n'est joignable que depuis un "
                        "reseau interne de confiance : le risque depend de l'exposition reseau "
                        "reelle, non testee ici."
                    ),
                    impact="Abus possible pour amplification DDoS si le serveur est exposable depuis l'exterieur.",
                    remediation="Restreindre la recursion aux clients internes legitimes (ACL de recursion).",
                    validation="Verifier la configuration de recursion et l'exposition reseau reelle du serveur.",
                    assets=[zone],
                    principal=zone,
                    condition_key="dns-open-recursion",
                    evidence=[
                        EvidenceRef(
                            source="dns",
                            object_type="zone",
                            object_id=zone,
                            attribute="recursion_available",
                            value="True",
                        )
                    ],
                    references=[_MS_DNS_DOC],
                )
            )
        return findings
