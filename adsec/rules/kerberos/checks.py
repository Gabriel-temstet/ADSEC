"""Controles Kerberos (AS-REP, Kerberoasting, delegations, chiffrement).

Ces controles detectent des CONDITIONS d'attaque a partir des attributs
LDAP deja collectes. Aucun ticket n'est demande, aucun hash n'est extrait,
aucun mot de passe n'est teste : la validation est laissee au pentester,
dans le cadre du ROE de la mission."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.attributes import (
    UAC_TRUSTED_FOR_DELEGATION,
    UAC_TRUSTED_TO_AUTH_FOR_DELEGATION,
    UAC_USE_DES_KEY_ONLY,
)
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
from adsec.rules.kerberos.common import (
    AES_ENCRYPTION_BITS,
    domain_controller_hosts,
    is_domain_controller,
    raw_attrs,
    spn_host,
    str_list,
    uac_of,
)

_MS_KERBEROS_DOC = "https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview"
_MS_DELEGATION_DOC = (
    "https://learn.microsoft.com/en-us/windows-server/security/kerberos/"
    "kerberos-constrained-delegation-overview"
)


def _sid_or_dn(row: dict[str, object]) -> str:
    return str(row.get("sid") or row["dn"])


def _ev(row: dict[str, object], attribute: str, value: str) -> list[EvidenceRef]:
    return [
        EvidenceRef(
            source="ldap",
            object_type="account",
            object_id=str(row["dn"]),
            attribute=attribute,
            value=value,
        )
    ]


def _requirements() -> list[DataRequirement]:
    return [DataRequirement(kind="users"), DataRequirement(kind="computers")]


class AsRepRoastable(CheckPlugin):
    id = "AD-KRB-001"
    name = "Pre-authentification Kerberos desactivee (AS-REP roasting)"
    version = "1.0.0"
    category = "kerberos"
    description = "Comptes actifs dont la pre-authentification Kerberos est desactivee."
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap", "kerberos"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for row in data.get("users"):
            if not row.get("enabled") or not row.get("pre_auth_not_required"):
                continue
            name = str(row["sam_account_name"])
            privileged = bool(row.get("admin_count"))
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Potential attack condition detected : AS-REP roasting possible ({name})",
                    severity=Severity.HIGH if privileged else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Le compte {name} n'exige pas de pre-authentification Kerberos "
                        "(DONT_REQ_PREAUTH). Toute personne pouvant joindre le KDC peut "
                        "obtenir des donnees chiffrees avec la cle du compte et tenter de "
                        "les casser hors ligne."
                    ),
                    why_detected="userAccountControl contient le drapeau DONT_REQ_PREAUTH (0x400000).",
                    why_risky=(
                        "Les donnees AS-REP sont derivees du mot de passe : un mot de passe "
                        "faible peut etre retrouve hors ligne, sans alerte cote domaine."
                        + (" Le compte est privilegie (adminCount=1)." if privileged else "")
                    ),
                    false_positive=(
                        "Compte legacy necessitant volontairement ce reglage ; le risque reste "
                        "reel mais peut etre attenue par un mot de passe long et aleatoire."
                    ),
                    impact="Compromission possible du compte si son mot de passe est faible.",
                    validation=(
                        f"Verifier l'attribut userAccountControl de {name} (Get-ADUser -Properties "
                        "DoesNotRequirePreAuth). La demande d'AS-REP et le cassage eventuel "
                        "sont a realiser manuellement, uniquement si le ROE l'autorise."
                    ),
                    remediation=(
                        f"Reactiver la pre-authentification pour {name}, ou imposer un mot de "
                        "passe long (>= 25 caracteres) et aleatoire s'il faut la conserver."
                    ),
                    assets=[str(row["dn"])],
                    principal=_sid_or_dn(row),
                    condition_key="asrep-roastable",
                    evidence=_ev(row, "userAccountControl", f"0x{uac_of(row):X}"),
                    references=[_MS_KERBEROS_DOC],
                    mitre_technique_id="T1558.004",
                )
            )
        return findings


class Kerberoastable(CheckPlugin):
    id = "AD-KRB-002"
    name = "Compte utilisateur avec SPN (Kerberoasting)"
    version = "1.0.0"
    category = "kerberos"
    description = "Comptes utilisateurs actifs porteurs d'un SPN."
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap", "kerberos"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for row in data.get("users"):
            spns = str_list(row.get("spns"))
            name = str(row["sam_account_name"])
            if not row.get("enabled") or not spns or name.lower() == "krbtgt":
                continue
            enc = raw_attrs(row).get("supported_encryption_types")
            aes = enc is not None and int(str(enc)) & AES_ENCRYPTION_BITS
            crypto_note = (
                "AES est declare comme supporte."
                if aes
                else "Aucun type de chiffrement AES explicitement configure : RC4 est "
                "probablement accepte, ce qui facilite le cassage hors ligne."
            )
            privileged = bool(row.get("admin_count"))
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Potential attack condition detected : Kerberoasting possible ({name})",
                    severity=Severity.HIGH if privileged else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Le compte utilisateur {name} porte {len(spns)} SPN. Tout utilisateur "
                        "authentifie peut demander un ticket de service chiffre avec la cle "
                        "de ce compte et tenter de le casser hors ligne."
                    ),
                    why_detected=f"attribut servicePrincipalName renseigne : {', '.join(spns)}.",
                    why_risky=(
                        "La robustesse du ticket depend uniquement du mot de passe du compte. "
                        + crypto_note
                        + (" Le compte est privilegie (adminCount=1)." if privileged else "")
                        + (
                            " Le mot de passe n'expire jamais."
                            if row.get("password_never_expires")
                            else ""
                        )
                    ),
                    false_positive=(
                        "Compte de service dote d'un mot de passe long et aleatoire (ou gMSA "
                        "modelise comme utilisateur) : la condition existe mais le cassage "
                        "est impraticable."
                    ),
                    impact="Compromission possible du compte de service si son mot de passe est faible.",
                    validation=(
                        f"Verifier les SPN de {name} et la robustesse/l'age de son mot de passe. "
                        "La demande de ticket et le cassage sont a realiser manuellement, "
                        "uniquement si le ROE l'autorise."
                    ),
                    remediation=(
                        "Migrer vers un compte de service gere (gMSA), sinon imposer un mot de "
                        "passe long et aleatoire, activer AES et retirer les SPN inutiles."
                    ),
                    assets=[str(row["dn"])],
                    principal=_sid_or_dn(row),
                    condition_key="kerberoastable",
                    evidence=_ev(row, "servicePrincipalName", "; ".join(spns)),
                    references=[_MS_KERBEROS_DOC],
                    mitre_technique_id="T1558.003",
                )
            )
        return findings


class UnconstrainedDelegation(CheckPlugin):
    id = "AD-KRB-003"
    name = "Delegation Kerberos non contrainte"
    version = "1.0.0"
    category = "kerberos"
    description = "Comptes (hors controleurs de domaine) autorises en delegation non contrainte."
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap", "kerberos"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        rows = [("computer", r) for r in data.get("computers")] + [
            ("user", r) for r in data.get("users")
        ]
        for kind, row in rows:
            flagged = bool(row.get("unconstrained_delegation")) or bool(
                uac_of(row) & UAC_TRUSTED_FOR_DELEGATION
            )
            if not flagged or not row.get("enabled") or is_domain_controller(row):
                continue  # les DC sont en delegation non contrainte par conception
            name = str(row["sam_account_name"])
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Potential attack condition detected : delegation non contrainte ({name})",
                    severity=Severity.HIGH,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Le compte {kind} {name} est autorise en delegation non contrainte "
                        "(TRUSTED_FOR_DELEGATION) et n'est pas un controleur de domaine."
                    ),
                    why_detected="userAccountControl contient TRUSTED_FOR_DELEGATION (0x80000) hors DC.",
                    why_risky=(
                        "Les tickets TGT des comptes qui s'authentifient aupres de ce compte y "
                        "sont mis en cache : sa compromission peut permettre d'usurper ces "
                        "comptes, y compris des comptes privilegies."
                    ),
                    false_positive=(
                        "Application legacy necessitant explicitement ce mode ; le risque reste "
                        "reel et justifie une migration vers une delegation contrainte/RBCD."
                    ),
                    impact="Elevation de privileges possible depuis la compromission de ce compte.",
                    validation=(
                        f"Verifier l'attribut TrustedForDelegation de {name} (Get-ADComputer/"
                        "Get-ADUser). Aucune exploitation n'est necessaire pour le confirmer."
                    ),
                    remediation=(
                        "Remplacer par une delegation contrainte ou RBCD, marquer les comptes "
                        "sensibles 'Le compte est sensible et ne peut pas etre delegue' et "
                        "utiliser le groupe Protected Users."
                    ),
                    assets=[str(row["dn"])],
                    principal=_sid_or_dn(row),
                    condition_key="unconstrained-delegation",
                    evidence=_ev(row, "userAccountControl", f"0x{uac_of(row):X}"),
                    references=[_MS_DELEGATION_DOC],
                )
            )
        return findings


class ConstrainedDelegationProtocolTransition(CheckPlugin):
    id = "AD-KRB-004"
    name = "Delegation contrainte avec transition de protocole"
    version = "1.0.0"
    category = "kerberos"
    description = (
        "Comptes disposant de msDS-AllowedToDelegateTo avec transition de protocole "
        "(TRUSTED_TO_AUTH_FOR_DELEGATION)."
    )
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap", "kerberos"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        dc_hosts = domain_controller_hosts(data)
        rows = [("computer", r) for r in data.get("computers")] + [
            ("user", r) for r in data.get("users")
        ]
        for kind, row in rows:
            targets = str_list(raw_attrs(row).get("delegate_to"))
            if not row.get("enabled") or not targets:
                continue
            if not uac_of(row) & UAC_TRUSTED_TO_AUTH_FOR_DELEGATION:
                continue
            name = str(row["sam_account_name"])
            dc_targets = [t for t in targets if spn_host(t) in dc_hosts]
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=(
                        "Potential attack condition detected : delegation contrainte avec "
                        f"transition de protocole ({name})"
                    ),
                    severity=Severity.HIGH if dc_targets else Severity.MEDIUM,
                    confidence=Confidence.HIGH,
                    description=(
                        f"Le compte {kind} {name} peut obtenir des tickets de service au nom "
                        f"de n'importe quel utilisateur (sans son authentification Kerberos) "
                        f"vers : {', '.join(targets)}."
                    ),
                    why_detected=(
                        "msDS-AllowedToDelegateTo est renseigne et userAccountControl contient "
                        "TRUSTED_TO_AUTH_FOR_DELEGATION (0x1000000)."
                    ),
                    why_risky=(
                        "La transition de protocole permet d'usurper un utilisateur arbitraire "
                        "vers les services cibles."
                        + (
                            f" Au moins une cible est un controleur de domaine : {', '.join(dc_targets)}."
                            if dc_targets
                            else ""
                        )
                    ),
                    false_positive=(
                        "Passerelle applicative legitime (ex: portail web vers un service "
                        "back-end) ; verifier que les cibles sont strictement necessaires."
                    ),
                    impact="Usurpation d'identite vers les services cibles depuis ce compte.",
                    validation=(
                        f"Verifier msDS-AllowedToDelegateTo et le drapeau de transition de {name}. "
                        "L'usurpation (S4U) n'est pas realisee par l'outil."
                    ),
                    remediation=(
                        "Restreindre la liste des cibles, eviter les cibles sensibles (DC), "
                        "preferer la delegation sans transition de protocole ou RBCD."
                    ),
                    assets=[str(row["dn"])],
                    principal=_sid_or_dn(row),
                    condition_key="constrained-protocol-transition",
                    evidence=_ev(row, "msDS-AllowedToDelegateTo", "; ".join(targets)),
                    references=[_MS_DELEGATION_DOC],
                )
            )
        return findings


class ResourceBasedConstrainedDelegation(CheckPlugin):
    id = "AD-KRB-005"
    name = "Delegation contrainte basee sur les ressources (RBCD) configuree"
    version = "1.0.0"
    category = "kerberos"
    description = "Objets dont msDS-AllowedToActOnBehalfOfOtherIdentity est renseigne."
    severity_hint = Severity.LOW
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap", "kerberos"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        rows = [("computer", r) for r in data.get("computers")] + [
            ("user", r) for r in data.get("users")
        ]
        for kind, row in rows:
            trustees = str_list(raw_attrs(row).get("rbcd_trustees"))
            if not trustees:
                continue
            name = str(row["sam_account_name"])
            sensitive = is_domain_controller(row) or bool(row.get("admin_count"))
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"RBCD configuree sur {name}",
                    severity=Severity.MEDIUM if sensitive else Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=(
                        f"Le {kind} {name} autorise {len(trustees)} principal(aux) a "
                        f"deleguer vers lui : {', '.join(trustees)}."
                    ),
                    why_detected="msDS-AllowedToActOnBehalfOfOtherIdentity est renseigne.",
                    why_risky=(
                        "Un principal figurant dans ce descripteur peut usurper des utilisateurs "
                        "vers cette ressource. La configuration est legitime mais sensible"
                        + (" ; la cible est un objet sensible." if sensitive else ".")
                    ),
                    false_positive=(
                        "RBCD volontairement deployee pour un service ; la confiance est "
                        "limitee a MEDIUM car l'intention ne peut pas etre deduite."
                    ),
                    impact=(
                        "Usurpation d'utilisateurs vers cette ressource par les principaux listes."
                    ),
                    validation=(
                        f"Comparer les principaux autorises sur {name} a l'architecture attendue "
                        "(Get-ADComputer -Properties PrincipalsAllowedToDelegateToAccount)."
                    ),
                    remediation=(
                        "Retirer les principaux non justifies et surveiller les modifications de "
                        "cet attribut (evenement 5136)."
                    ),
                    assets=[str(row["dn"])],
                    principal=_sid_or_dn(row),
                    condition_key="rbcd-configured",
                    evidence=_ev(
                        row, "msDS-AllowedToActOnBehalfOfOtherIdentity", "; ".join(trustees)
                    ),
                    references=[_MS_DELEGATION_DOC],
                )
            )
        return findings


class WeakKerberosEncryption(CheckPlugin):
    id = "AD-KRB-006"
    name = "Chiffrement Kerberos faible"
    version = "1.0.0"
    category = "kerberos"
    description = "Comptes limites a DES ou sans AES explicitement configure."
    severity_hint = Severity.MEDIUM
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap", "kerberos"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return _requirements()

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        rows = [("computer", r) for r in data.get("computers")] + [
            ("user", r) for r in data.get("users")
        ]
        for kind, row in rows:
            if not row.get("enabled"):
                continue
            name = str(row["sam_account_name"])
            uac = uac_of(row)
            enc = raw_attrs(row).get("supported_encryption_types")
            des_only = bool(uac & UAC_USE_DES_KEY_ONLY)
            explicit_no_aes = enc is not None and not int(str(enc)) & AES_ENCRYPTION_BITS
            if not des_only and not explicit_no_aes:
                continue
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"Chiffrement Kerberos faible configure ({name})",
                    severity=Severity.HIGH if des_only else Severity.MEDIUM,
                    confidence=Confidence.HIGH if des_only else Confidence.MEDIUM,
                    description=(
                        f"Le {kind} {name} est "
                        + (
                            "limite a DES (USE_DES_KEY_ONLY)."
                            if des_only
                            else f"configure sans AES (msDS-SupportedEncryptionTypes={enc})."
                        )
                    ),
                    why_detected=(
                        "userAccountControl contient USE_DES_KEY_ONLY (0x200000)."
                        if des_only
                        else "msDS-SupportedEncryptionTypes est explicite et n'inclut ni AES128 ni AES256."
                    ),
                    why_risky="Les algorithmes DES/RC4 sont obsoletes et facilitent le cassage hors ligne.",
                    false_positive=(
                        "Systeme legacy incapable d'utiliser AES ; la valeur peut aussi etre "
                        "ecrasee par une GPO cote client, d'ou une confiance moderee hors DES."
                    ),
                    impact="Resistance reduite des tickets Kerberos face au cassage hors ligne.",
                    validation=(
                        f"Verifier msDS-SupportedEncryptionTypes et les options de compte de {name}."
                    ),
                    remediation="Activer AES128/AES256, desactiver DES et planifier la sortie de RC4.",
                    assets=[str(row["dn"])],
                    principal=_sid_or_dn(row),
                    condition_key="weak-encryption",
                    evidence=_ev(row, "userAccountControl", f"0x{uac:X} enc={enc}"),
                    references=[_MS_KERBEROS_DOC],
                )
            )
        return findings
