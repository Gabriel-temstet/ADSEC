"""Controles SMB : SMBv1, signing, session anonyme, partages accessibles.

Ces controles consomment les donnees deja collectees par `SmbCollector`
(table `smb_hosts`/`smb_shares` normalisee) - aucune connexion reseau
n'est faite depuis un plugin : la regle du produit separe strictement
collecte et analyse.
"""

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
from adsec.rules.kerberos.common import domain_controller_hosts

_MS_SMB_SIGNING_DOC = (
    "https://learn.microsoft.com/en-us/troubleshoot/windows-server/networking/"
    "overview-server-message-block-signing"
)
_MS_SMB1_DOC = "https://learn.microsoft.com/en-us/windows-server/storage/file-server/troubleshoot/detect-enable-and-disable-smbv1-v2-v3"


def _requirements() -> list[DataRequirement]:
    return [DataRequirement(kind="smb_hosts", description="Hotes et partages SMB collectes")]


class Smb1Enabled(CheckPlugin):
    id = "AD-SMB-001"
    name = "SMBv1 actif"
    version = "1.0.0"
    category = "smb"
    description = "Detecte les hotes qui negocient encore le protocole SMBv1 obsolete."
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["smb"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for host in data.get("smb_hosts"):
            if not host.get("is_smb1"):
                continue
            hostname = str(host["hostname"])
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"SMBv1 actif sur {hostname}",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=f"L'hote {hostname} negocie encore le protocole SMBv1.",
                    why_detected="Le dialecte negocie lors de la connexion est SMBv1 (NT LM 0.12).",
                    why_risky=(
                        "SMBv1 est obsolete, sans les protections modernes (signing renforce, "
                        "chiffrement) et vulnerable a des exploits connus (ex: EternalBlue)."
                    ),
                    false_positive="Aucun : la negociation du dialecte est une observation directe.",
                    impact="Surface d'attaque accrue (exploits SMBv1 connus, absence de protections modernes).",
                    validation=f"Confirmer via 'Get-SmbServerConfiguration' sur {hostname} (EnableSMB1Protocol).",
                    remediation=f"Desactiver SMBv1 sur {hostname} (Disable-WindowsOptionalFeature SMB1Protocol).",
                    assets=[hostname],
                    principal=hostname,
                    condition_key="smb1-enabled",
                    evidence=[
                        EvidenceRef(
                            source="smb",
                            object_type="host",
                            object_id=hostname,
                            attribute="dialect",
                            value=str(host.get("dialect")),
                        )
                    ],
                    references=[_MS_SMB1_DOC],
                    mitre_technique_id="T1210",
                )
            )
        return findings


class SmbSigningNotRequired(CheckPlugin):
    id = "AD-SMB-002"
    name = "Signature SMB non exigee"
    version = "1.0.0"
    category = "smb"
    description = "Detecte les hotes qui n'exigent pas la signature des sessions SMB."
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["smb"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [*_requirements(), DataRequirement(kind="computers")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        dc_hosts = domain_controller_hosts(data)
        for host in data.get("smb_hosts"):
            if host.get("signing_required"):
                continue
            hostname = str(host["hostname"])
            is_dc = hostname.lower() in dc_hosts
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Signature SMB non exigee sur {hostname}",
                    severity=Severity.HIGH if is_dc else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=f"L'hote {hostname} n'exige pas la signature des sessions SMB.",
                    why_detected="La negociation SMB indique que la signature n'est pas obligatoire.",
                    why_risky=(
                        "Sans signature obligatoire, un attaquant en position de "
                        "l'interception (NTLM relay) peut relayer une authentification "
                        "vers ce service."
                        + (" Cet hote est un controleur de domaine." if is_dc else "")
                    ),
                    false_positive="Aucun : la negociation de signature est une observation directe.",
                    impact="Relais NTLM possible vers ce service, pouvant mener a une elevation de privileges.",
                    validation=(
                        f"Confirmer via 'Get-SmbServerConfiguration' sur {hostname} "
                        "(RequireSecuritySignature)."
                    ),
                    remediation=f"Activer 'Microsoft network server: Digitally sign communications (always)' sur {hostname}.",
                    assets=[hostname],
                    principal=hostname,
                    condition_key="smb-signing-not-required",
                    evidence=[
                        EvidenceRef(
                            source="smb",
                            object_type="host",
                            object_id=hostname,
                            attribute="signing_required",
                            value="False",
                        )
                    ],
                    references=[_MS_SMB_SIGNING_DOC],
                    mitre_technique_id="T1557.001",
                )
            )
        return findings


class SmbNullSessionAllowed(CheckPlugin):
    id = "AD-SMB-003"
    name = "Session SMB anonyme/invite acceptee"
    version = "1.0.0"
    category = "smb"
    description = "Detecte les hotes qui acceptent une session SMB anonyme ou invite."
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["smb"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for host in data.get("smb_hosts"):
            if not host.get("guest_or_anonymous"):
                continue
            hostname = str(host["hostname"])
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Session SMB anonyme/invite acceptee sur {hostname}",
                    severity=Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"L'hote {hostname} a accepte une authentification SMB sans "
                        "identifiants valides (session nulle ou invite)."
                    ),
                    why_detected="La session etablie sans identifiants est marquee invite/anonyme par le serveur.",
                    why_risky=(
                        "Une session anonyme permet souvent d'enumerer partages, utilisateurs "
                        "ou politiques sans authentification."
                    ),
                    false_positive="Aucun : le statut de la session est renvoye directement par le serveur.",
                    impact="Reconnaissance non authentifiee facilitee (partages, comptes, politique).",
                    validation=f"Verifier RestrictAnonymous et l'acces invite sur {hostname}.",
                    remediation="Desactiver le compte invite et durcir RestrictAnonymous/RestrictAnonymousSAM.",
                    assets=[hostname],
                    principal=hostname,
                    condition_key="smb-null-session",
                    evidence=[
                        EvidenceRef(
                            source="smb",
                            object_type="host",
                            object_id=hostname,
                            attribute="guest_or_anonymous",
                            value="True",
                        )
                    ],
                    references=[_MS_SMB_SIGNING_DOC],
                    mitre_technique_id="T1135",
                )
            )
        return findings


class ShareReadableAnonymously(CheckPlugin):
    id = "AD-SMB-004"
    name = "Partage accessible anonymement"
    version = "1.0.0"
    category = "smb"
    description = "Detecte les partages non caches accessibles via une session anonyme/invite."
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = ["smb"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for host in data.get("smb_hosts"):
            hostname = str(host["hostname"])
            shares = host.get("shares")
            for share in shares if isinstance(shares, list) else []:
                if not isinstance(share, dict) or not share.get("anonymous_readable"):
                    continue
                if share.get("is_hidden_admin_share"):
                    continue  # deja couvert par la session anonyme elle-meme (AD-SMB-003)
                name = str(share["name"])
                sensitive_name = name.upper() in ("SYSVOL", "NETLOGON")
                findings.append(
                    new_finding(
                        rule_id=self.id,
                        category=self.category,
                        title=f"Partage {name} accessible anonymement sur {hostname}",
                        severity=Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"Le partage {name} sur {hostname} est accessible via une session "
                            "SMB anonyme ou invite."
                        ),
                        why_detected="La connexion a l'arborescence du partage a reussi sans identifiants.",
                        why_risky=(
                            "Un attaquant non authentifie peut parcourir ce partage et y trouver "
                            "des donnees ou fichiers de configuration sensibles."
                            + (
                                " SYSVOL/NETLOGON sont normalement lisibles par les utilisateurs "
                                "authentifies, pas par des sessions anonymes."
                                if sensitive_name
                                else ""
                            )
                        ),
                        false_positive=(
                            "Partage intentionnellement public (ex: documentation, outils) ; "
                            "verifier le contenu reel avant de le considerer critique."
                        ),
                        impact="Divulgation d'information, potentiellement de secrets ou scripts sensibles.",
                        validation=f"Lister le contenu de \\\\{hostname}\\{name} avec un client SMB anonyme.",
                        remediation="Retirer l'acces Everyone/Anonymous sur ce partage (ACL de partage et NTFS).",
                        assets=[f"{hostname}\\{name}"],
                        principal=f"{hostname}\\{name}",
                        condition_key="share-anonymous-read",
                        evidence=[
                            EvidenceRef(
                                source="smb",
                                object_type="share",
                                object_id=f"{hostname}\\{name}",
                                attribute="anonymous_readable",
                                value="True",
                            )
                        ],
                        references=[_MS_SMB_SIGNING_DOC],
                        mitre_technique_id="T1039",
                    )
                )
        return findings
