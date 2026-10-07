"""AD-ACL-005 : droits de replication d'annuaire sur la racine du domaine
detenus par un principal non integre (condition DCSync)."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.rights import RIGHT_DS_CONTROL_ACCESS, has_right, is_full_control
from adsec.core.models.enums import AccessLevel, Confidence, Severity
from adsec.rules.acl.common import trustee_label
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

GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


class ReplicationRightsOnDomain(CheckPlugin):
    id = "AD-ACL-005"
    name = "Droits de replication sur la racine du domaine"
    version = "1.0.0"
    category = "acl"
    description = (
        "Detecte les principaux non integres disposant de DS-Replication-Get-Changes(-All) "
        "sur la racine du domaine (condition DCSync)."
    )
    severity_hint = Severity.CRITICAL
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [
            DataRequirement(kind="acls"),
            DataRequirement(kind="users"),
            DataRequirement(kind="groups"),
            DataRequirement(kind="computers"),
        ]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        findings: list[Finding] = []
        for acl in data.get("acls"):
            if acl.get("object_type") != "domain":
                continue
            domain_dn = str(acl["object_dn"])
            tokens: dict[str, set[str]] = {}
            permissions = acl.get("permissions")
            for perm in permissions if isinstance(permissions, list) else []:
                if not isinstance(perm, dict) or perm.get("ace_type") not in (
                    "ALLOWED",
                    "ALLOWED_OBJECT",
                ):
                    continue
                sid = str(perm["trustee_sid"])
                if is_well_known_safe_trustee(sid):
                    continue
                mask = int(str(perm["rights_mask"]))
                guid = (
                    str(perm["object_type_guid"]).lower() if perm.get("object_type_guid") else None
                )
                found = tokens.setdefault(sid, set())
                if is_full_control(mask) or (
                    has_right(mask, RIGHT_DS_CONTROL_ACCESS) and guid is None
                ):
                    found.add("all")
                elif has_right(mask, RIGHT_DS_CONTROL_ACCESS) and guid == GET_CHANGES:
                    found.add("changes")
                elif has_right(mask, RIGHT_DS_CONTROL_ACCESS) and guid == GET_CHANGES_ALL:
                    found.add("changes_all")

            for sid, found in sorted(tokens.items()):
                complete = "all" in found or {"changes", "changes_all"} <= found
                if not complete and "changes_all" not in found:
                    continue
                trustee = trustee_label(data, sid)
                findings.append(
                    new_finding(
                        rule_id=self.id,
                        category=self.category,
                        title=f"Potential attack condition detected : droits de replication (DCSync) pour {trustee}",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.HIGH if complete else Confidence.MEDIUM,
                        description=(
                            f"{trustee} dispose de droits de replication d'annuaire sur {domain_dn}, "
                            "sans etre un groupe integre autorise (Domain Controllers, "
                            "Domain Admins, Enterprise Admins, Administrators)."
                        ),
                        why_detected=(
                            f"ACE sur la racine du domaine accordant : {', '.join(sorted(found))} "
                            "(all = controle total/tous les droits etendus)."
                        ),
                        why_risky=(
                            "Ces droits permettent de se faire passer pour un controleur de domaine "
                            "et de demander la replication des secrets du domaine, y compris les "
                            "hashes de mots de passe de tous les comptes."
                        ),
                        false_positive=(
                            "Compte de synchronisation legitime (ex: Azure AD Connect, outil de "
                            "sauvegarde/migration). Confiance MEDIUM si seul Get-Changes-All est "
                            "present, la replication necessitant aussi Get-Changes."
                        ),
                        impact="Extraction possible de tous les secrets du domaine (compromission totale).",
                        validation=(
                            f"Verifier les droits de {trustee} sur la racine du domaine (dsacls "
                            f"\"{domain_dn}\") et l'usage attendu du compte. L'operation de "
                            "replication n'est jamais realisee par l'outil."
                        ),
                        remediation=(
                            "Retirer les droits de replication non justifies ; pour un compte de "
                            "synchronisation legitime, le durcir (mot de passe long, restriction "
                            "de connexion, surveillance de son usage)."
                        ),
                        assets=[domain_dn],
                        principal=sid,
                        condition_key="dcsync-rights",
                        evidence=[
                            EvidenceRef(
                                source="ldap",
                                object_type="domain",
                                object_id=domain_dn,
                                attribute="nTSecurityDescriptor",
                                value=f"trustee={sid} rights={','.join(sorted(found))}",
                            )
                        ],
                        references=[
                            "https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all"
                        ],
                        mitre_technique_id="T1003.006",
                    )
                )
        return findings
