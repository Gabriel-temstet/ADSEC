"""Controles GPO (metadonnees, liens et ACL collectes via LDAP).

Le contenu des GPO (GptTmpl.inf, scripts, taches planifiees dans SYSVOL)
necessite un acces SMB et n'est pas encore analyse : ces controles portent
uniquement sur qui peut modifier une GPO et sur son usage."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.rights import (
    RIGHT_DS_WRITE_PROP,
    RIGHT_WRITE_DAC,
    RIGHT_WRITE_OWNER,
    has_right,
    is_full_control,
    is_generic_write,
)
from adsec.core.models.enums import AccessLevel, Confidence, Severity
from adsec.rules.acl.common import is_broad_principal, trustee_label
from adsec.rules.acl.well_known_sids import is_well_known_safe_trustee
from adsec.rules.base import (
    CheckPlugin,
    DataRequirement,
    EvidenceRef,
    Finding,
    NormalizedData,
    ScanContext,
)
from adsec.rules.factory import new_finding

_GROUP_POLICY_CREATOR_OWNERS_RID = "520"
_GPO_DOC = "https://learn.microsoft.com/en-us/previous-versions/windows/desktop/policy/group-policy-objects"


def _grants_gpo_write(perm: dict[str, object]) -> bool:
    mask = int(str(perm["rights_mask"]))
    guid = str(perm["object_type_guid"]) if perm.get("object_type_guid") else None
    if is_full_control(mask) or has_right(mask, RIGHT_WRITE_DAC, RIGHT_WRITE_OWNER):
        return True
    if is_generic_write(mask, guid):
        return True
    # WriteProperty sur toutes les proprietes (pas de GUID cible)
    return has_right(mask, RIGHT_DS_WRITE_PROP) and guid is None


def _gpo_by_dn(data: NormalizedData) -> dict[str, dict[str, object]]:
    return {str(g["dn"]).lower(): g for g in data.get("gpos")}


def _links(gpo: dict[str, object]) -> list[dict[str, object]]:
    links = gpo.get("links")
    return [x for x in links if isinstance(x, dict)] if isinstance(links, list) else []


def _is_critical_scope(gpo: dict[str, object], domain_dns: set[str]) -> bool:
    for link in _links(gpo):
        target = str(link["target_dn"])
        if target.lower() in domain_dns or "ou=domain controllers" in target.lower():
            return True
    return False


class GpoWritableByNonAdmin(CheckPlugin):
    id = "AD-GPO-001"
    name = "GPO modifiable par un principal non integre"
    version = "1.0.0"
    category = "gpo"
    description = "Detecte les droits d'ecriture sur une GPO accordes a un principal non integre."
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [
            DataRequirement(kind="acls"),
            DataRequirement(kind="gpos"),
            DataRequirement(kind="users"),
            DataRequirement(kind="groups"),
            DataRequirement(kind="computers"),
        ]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        gpos = _gpo_by_dn(data)
        domain_dns = {
            str(a["object_dn"]).lower()
            for a in data.get("acls")
            if a.get("object_type") == "domain"
        }
        findings: list[Finding] = []
        for acl in data.get("acls"):
            if acl.get("object_type") != "gpo":
                continue
            dn = str(acl["object_dn"])
            gpo = gpos.get(dn.lower())
            name = str(gpo["display_name"]) if gpo else dn
            linked = _links(gpo) if gpo else []
            critical_scope = bool(gpo) and _is_critical_scope(gpo, domain_dns)  # type: ignore[arg-type]
            permissions = acl.get("permissions")
            for perm in permissions if isinstance(permissions, list) else []:
                if not isinstance(perm, dict) or perm.get("ace_type") not in (
                    "ALLOWED",
                    "ALLOWED_OBJECT",
                ):
                    continue
                sid = str(perm["trustee_sid"])
                if is_well_known_safe_trustee(sid) or sid.endswith(
                    f"-{_GROUP_POLICY_CREATOR_OWNERS_RID}"
                ):
                    continue
                if not _grants_gpo_write(perm):
                    continue
                trustee = trustee_label(data, sid)
                severe = critical_scope or is_broad_principal(sid)
                targets = ", ".join(str(link["target_dn"]) for link in linked) or "aucun lien connu"
                findings.append(
                    new_finding(
                        rule_id=self.id,
                        category=self.category,
                        title=f"GPO modifiable par un principal non integre : {trustee} sur {name}",
                        severity=Severity.CRITICAL if severe else Severity.HIGH,
                        confidence=Confidence.HIGH,
                        description=(
                            f"{trustee} peut modifier la GPO {name}, appliquee a : {targets}."
                        ),
                        why_detected=(
                            f"ACE {perm.get('ace_type')} avec droits "
                            f"{', '.join(str(r) for r in perm.get('rights', []))} "
                            f"sur l'objet {dn}."
                        ),
                        why_risky=(
                            "Modifier une GPO permet de deployer des parametres, scripts ou taches "
                            "planifiees sur tous les objets auxquels elle s'applique."
                            + (
                                " La GPO est liee a la racine du domaine ou aux controleurs "
                                "de domaine."
                                if critical_scope
                                else ""
                            )
                        ),
                        false_positive=(
                            "Delegation d'administration des GPO volontaire (equipe poste de "
                            "travail, par exemple) ; verifier que le perimetre lie correspond."
                        ),
                        impact="Execution de code ou changement de configuration sur les cibles de la GPO.",
                        validation=(
                            f"Verifier la delegation sur {name} (GPMC > Delegation ou Get-GPPermission) "
                            "et son perimetre de liaison. Aucune modification n'est realisee."
                        ),
                        remediation=(
                            "Retirer le droit d'ecriture non justifie et limiter la delegation aux "
                            "groupes d'administration GPO dedies."
                        ),
                        assets=[dn],
                        principal=sid,
                        condition_key="gpo-write",
                        evidence=[
                            EvidenceRef(
                                source="ldap",
                                object_type="gpo",
                                object_id=dn,
                                attribute="nTSecurityDescriptor",
                                value=f"{perm.get('ace_type')} trustee={sid}",
                            )
                        ],
                        references=[_GPO_DOC],
                    )
                )
        return findings


class UnlinkedGpo(CheckPlugin):
    id = "AD-GPO-002"
    name = "GPO non liee"
    version = "1.0.0"
    category = "gpo"
    description = "GPO existantes sans aucun lien vers le domaine ou une OU."
    severity_hint = Severity.LOW
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [DataRequirement(kind="gpos")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings = []
        for gpo in data.get("gpos"):
            if _links(gpo):
                continue
            name = str(gpo["display_name"])
            dn = str(gpo["dn"])
            findings.append(
                new_finding(
                    rule_id=self.id,
                    category=self.category,
                    title=f"GPO non liee : {name}",
                    severity=Severity.LOW,
                    confidence=Confidence.MEDIUM,
                    description=f"La GPO {name} n'est liee a aucune OU ni a la racine du domaine.",
                    why_detected="Aucun attribut gPLink du domaine ou des OUs ne reference cette GPO.",
                    why_risky=(
                        "Une GPO orpheline est de la dette de configuration : elle peut etre "
                        "reliee par erreur ou contenir des parametres obsoletes/sensibles."
                    ),
                    false_positive=(
                        "Les liens vers des sites AD ne sont pas collectes : la GPO peut etre "
                        "utilisee via un lien de site (confiance limitee a MEDIUM)."
                    ),
                    impact="Hygiene de configuration ; risque indirect limite.",
                    validation=f"Verifier dans GPMC (onglet Etendue) que {name} n'est liee a aucun site.",
                    remediation="Supprimer la GPO si elle est inutile, sinon documenter son usage.",
                    assets=[dn],
                    principal=str(gpo["guid"]),
                    condition_key="gpo-unlinked",
                    evidence=[
                        EvidenceRef(
                            source="ldap",
                            object_type="gpo",
                            object_id=dn,
                            attribute="gPLink",
                            value="aucun lien (domaine/OU)",
                        )
                    ],
                    references=[_GPO_DOC],
                )
            )
        return findings
