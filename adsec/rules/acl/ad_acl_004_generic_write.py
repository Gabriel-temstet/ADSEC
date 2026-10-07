"""AD-ACL-004 : GenericWrite (ecriture sur les proprietes) sur un objet sensible."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.rights import is_full_control, is_generic_write
from adsec.core.models.enums import AccessLevel, Severity
from adsec.rules.acl.common import build_acl_finding, iter_dangerous_aces
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext


def _is_generic_write_only(perm: dict[str, object]) -> bool:
    mask = int(str(perm["rights_mask"]))
    guid = perm.get("object_type_guid")
    return is_generic_write(mask, None if guid is None else str(guid)) and not is_full_control(mask)


class GenericWriteOnPrivilegedObject(CheckPlugin):
    id = "AD-ACL-004"
    name = "GenericWrite sur un objet sensible"
    version = "1.0.0"
    category = "acl"
    description = (
        "Detecte les ACE accordant GenericWrite (ecriture sur les proprietes) a "
        "un principal non integre sur un objet sensible."
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
                title="GenericWrite accorde sur un objet sensible",
                right_label="GenericWrite (ecriture des proprietes)",
                impact=(
                    "Le detenteur peut modifier des attributs de l'objet (ex: SPN, "
                    "script de connexion, delegation), ce qui peut faciliter une "
                    "elevation de privileges selon le type d'objet."
                ),
                explanation="L'impact reel depend des attributs modifiables sur cet objet.",
            )
            for ace in iter_dangerous_aces(data, _is_generic_write_only)
        ]
