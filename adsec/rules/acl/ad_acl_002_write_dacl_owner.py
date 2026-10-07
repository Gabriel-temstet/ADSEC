"""AD-ACL-002 : WriteDACL / WriteOwner sur un objet sensible."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.rights import (
    RIGHT_WRITE_DAC,
    RIGHT_WRITE_OWNER,
    has_right,
    is_full_control,
)
from adsec.core.models.enums import AccessLevel, Severity
from adsec.rules.acl.common import build_acl_finding, iter_dangerous_aces
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext


def _is_write_dacl_or_owner_only(perm: dict[str, object]) -> bool:
    mask = int(str(perm["rights_mask"]))
    # Le controle total est deja remonte par AD-ACL-001 (deduplication).
    return has_right(mask, RIGHT_WRITE_DAC, RIGHT_WRITE_OWNER) and not is_full_control(mask)


class WriteDaclOrOwnerOnPrivilegedObject(CheckPlugin):
    id = "AD-ACL-002"
    name = "WriteDACL / WriteOwner sur un objet sensible"
    version = "1.0.0"
    category = "acl"
    description = (
        "Detecte les ACE accordant WriteDACL ou WriteOwner a un principal non "
        "integre sur un objet sensible."
    )
    severity_hint = Severity.HIGH
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
        return [
            build_acl_finding(
                data,
                ace,
                rule_id=self.id,
                category=self.category,
                title="WriteDACL/WriteOwner accorde sur un objet sensible",
                right_label="WriteDACL et/ou WriteOwner",
                impact=(
                    "Le detenteur peut modifier la DACL ou le proprietaire de l'objet et "
                    "ainsi s'attribuer lui-meme n'importe quel autre droit sur celui-ci."
                ),
                explanation=("Ces droits permettent d'obtenir indirectement le controle total."),
            )
            for ace in iter_dangerous_aces(data, _is_write_dacl_or_owner_only)
        ]
