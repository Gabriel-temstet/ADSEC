"""AD-ACL-001 : controle total (GenericAll / Full Control) sur un objet sensible."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.rights import is_full_control
from adsec.core.models.enums import AccessLevel, Severity
from adsec.rules.acl.common import build_acl_finding, iter_dangerous_aces
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext


class GenericAllOnPrivilegedObject(CheckPlugin):
    id = "AD-ACL-001"
    name = "Controle total sur un objet sensible"
    version = "1.0.0"
    category = "acl"
    description = (
        "Detecte les ACE accordant GenericAll / Full Control a un principal non "
        "integre sur un compte a privileges, un groupe privilegie ou un ordinateur "
        "en delegation non contrainte."
    )
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [
            DataRequirement(kind="acls", description="ACL des objets AD"),
            DataRequirement(kind="users"),
            DataRequirement(kind="groups"),
            DataRequirement(kind="computers"),
        ]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        return [
            build_acl_finding(
                data,
                ace,
                rule_id=self.id,
                category=self.category,
                title="Controle total accorde sur un objet sensible",
                right_label="GenericAll (controle total)",
                impact=(
                    "Le detenteur peut modifier l'objet sans restriction (reinitialiser "
                    "un mot de passe, changer l'appartenance, modifier la DACL), ce qui "
                    "ouvre une elevation de privileges vers cet objet."
                ),
                explanation=("Ce droit equivaut a la prise de controle complete de l'objet cible."),
            )
            for ace in iter_dangerous_aces(
                data, lambda p: is_full_control(int(str(p["rights_mask"])))
            )
        ]
