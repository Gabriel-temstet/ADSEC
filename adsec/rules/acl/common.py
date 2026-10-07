"""Helpers partages par les plugins d'analyse ACL."""

from __future__ import annotations

from collections.abc import Callable, Iterator
from dataclasses import dataclass

from adsec.core.models.enums import Confidence, Severity
from adsec.rules.acl.well_known_sids import is_well_known_safe_trustee
from adsec.rules.base import EvidenceRef, Finding, NormalizedData


@dataclass(frozen=True)
class PrivilegedObject:
    dn: str
    object_type: str
    reason: str


def index_privileged_objects(data: NormalizedData) -> dict[str, PrivilegedObject]:
    """Construit un index (dn en minuscules -> PrivilegedObject) des objets
    consideres comme sensibles a partir des donnees deja collectees :
    comptes avec adminCount=1, groupes bien connus comme privilegies,
    ordinateurs en delegation non contrainte."""
    index: dict[str, PrivilegedObject] = {}

    for row in data.get("users"):
        if row.get("admin_count"):
            dn = str(row["dn"])
            index[dn.lower()] = PrivilegedObject(dn, "user", "adminCount=1 (compte a privileges)")

    for row in data.get("groups"):
        if row.get("privileged"):
            dn = str(row["dn"])
            index[dn.lower()] = PrivilegedObject(dn, "group", "groupe integre a privileges")

    for row in data.get("computers"):
        if row.get("unconstrained_delegation"):
            dn = str(row["dn"])
            index[dn.lower()] = PrivilegedObject(
                dn, "computer", "delegation Kerberos non contrainte"
            )

    return index


_BROAD_PRINCIPAL_SIDS = frozenset({"S-1-1-0", "S-1-5-11", "S-1-5-7"})
_DOMAIN_USERS_RID = "513"
_DOMAIN_COMPUTERS_RID = "515"


def is_broad_principal(sid: str) -> bool:
    """Principal tres large (Everyone, Authenticated Users, Domain Users...) :
    un droit dangereux accorde a ce type de principal est bien plus grave
    qu'un droit accorde a un compte nominatif."""
    if sid in _BROAD_PRINCIPAL_SIDS:
        return True
    return sid.rsplit("-", 1)[-1] in {_DOMAIN_USERS_RID, _DOMAIN_COMPUTERS_RID}


def trustee_label(data: NormalizedData, sid: str) -> str:
    """Resout un SID en nom lisible a partir des objets collectes."""
    for table in ("users", "groups", "computers"):
        for row in data.get(table):
            if row.get("sid") == sid:
                return f"{row.get('sam_account_name')} ({sid})"
    return sid


@dataclass(frozen=True)
class DangerousAce:
    acl: dict[str, object]
    permission: dict[str, object]
    target: PrivilegedObject

    @property
    def trustee_sid(self) -> str:
        return str(self.permission["trustee_sid"])

    @property
    def inherited(self) -> bool:
        return bool(self.permission.get("inherited"))


def iter_dangerous_aces(
    data: NormalizedData, matcher: Callable[[dict[str, object]], bool]
) -> Iterator[DangerousAce]:
    """Parcourt les ACE ALLOWED accordees a des trustees non 'bien connus'
    sur des objets sensibles, et retient celles qui satisfont `matcher`."""
    privileged = index_privileged_objects(data)
    for acl in data.get("acls"):
        target = privileged.get(str(acl["object_dn"]).lower())
        if target is None:
            continue
        permissions = acl.get("permissions") or []
        if not isinstance(permissions, list):
            continue
        for perm in permissions:
            if not isinstance(perm, dict):
                continue
            if perm.get("ace_type") not in ("ALLOWED", "ALLOWED_OBJECT"):
                continue
            if is_well_known_safe_trustee(str(perm.get("trustee_sid"))):
                continue
            if matcher(perm):
                yield DangerousAce(acl=acl, permission=perm, target=target)


def build_acl_finding(
    data: NormalizedData,
    ace: DangerousAce,
    *,
    rule_id: str,
    category: str,
    title: str,
    right_label: str,
    impact: str,
    explanation: str,
) -> Finding:
    """Construit un Finding standardise pour une ACE dangereuse.

    Severite : HIGH par defaut ; CRITICAL si le trustee est un principal
    tres large (Everyone / Authenticated Users / Domain Users). Confiance
    HIGH : l'ACE a ete lue directement dans le descripteur de securite."""
    broad = is_broad_principal(ace.trustee_sid)
    severity = Severity.CRITICAL if broad else Severity.HIGH
    trustee = trustee_label(data, ace.trustee_sid)
    dn = ace.target.dn
    rights = ", ".join(str(r) for r in ace.permission.get("rights", [])) or "n/a"  # type: ignore[attr-defined]

    return Finding(
        rule_id=rule_id,
        title=f"{title} : {trustee} sur {dn}",
        category=category,
        severity=severity,
        confidence=Confidence.HIGH,
        description=(
            f"{trustee} dispose du droit {right_label} sur {dn}, objet sensible "
            f"({ace.target.reason}). {explanation}"
        ),
        technical_details=(
            f"Pourquoi detecte : ACE {ace.permission.get('ace_type')} dans la DACL de {dn} "
            f"(droits decodes : {rights} ; masque 0x{int(str(ace.permission['rights_mask'])):08X} ; "
            f"heritee : {'oui' if ace.inherited else 'non'}). "
            f"Pourquoi risque : {impact} "
            "Faux positif possible : delegation d'administration volontaire et documentee "
            "(ex: groupe d'administration dedie, outil de provisioning)."
        ),
        impact=impact,
        validation_procedure=(
            f"Verifier l'ACL de {dn} (dsacls, ADUC onglet Securite avancee ou "
            "Get-Acl) et confirmer que ce droit correspond a une delegation attendue "
            "dans le ROE/le modele d'administration du client. Aucune exploitation "
            "n'est realisee ni necessaire pour valider la presence de l'ACE."
        ),
        remediation=(
            f"Retirer l'ACE de {trustee} sur {dn} si elle n'est pas justifiee, verifier "
            "l'heritage depuis l'OU parente, et appliquer le principe du moindre "
            "privilege (AdminSDHolder/SDProp pour les objets proteges)."
        ),
        affected_assets=[dn],
        principal=ace.trustee_sid,
        condition_key=right_label,
        evidence=[
            EvidenceRef(
                source="ldap",
                object_type=ace.target.object_type,
                object_id=dn,
                attribute="nTSecurityDescriptor",
                value=f"{ace.permission.get('ace_type')} trustee={ace.trustee_sid} rights={rights}",
            )
        ],
        references=[
            "https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/appendix-c--protected-accounts-and-groups-in-active-directory",
        ],
        # Volontairement aucun mapping MITRE ATT&CK : aucune technique ne
        # correspond de facon fiable a l'abus d'ACL d'objets AD, et le
        # produit ne fabrique jamais de correspondance approximative.
        mitre_technique_id=None,
    )
