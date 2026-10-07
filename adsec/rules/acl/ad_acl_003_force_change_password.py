"""AD-ACL-003 : droit de reinitialiser le mot de passe d'un compte sensible."""

from __future__ import annotations

from typing import ClassVar

from adsec.collectors.ldap.rights import RIGHT_DS_CONTROL_ACCESS, has_right, is_full_control
from adsec.core.models.enums import AccessLevel, Severity
from adsec.rules.acl.common import build_acl_finding, iter_dangerous_aces
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext

_FORCE_CHANGE_PASSWORD_GUIDS = frozenset({"00299570-246d-11d0-a768-00aa006e0529"})


def _grants_password_reset(perm: dict[str, object]) -> bool:
    mask = int(str(perm["rights_mask"]))
    if is_full_control(mask) or not has_right(mask, RIGHT_DS_CONTROL_ACCESS):
        return False
    guid = perm.get("object_type_guid")
    # ExtendedRight cible sur ForceChangePassword, ou ExtendedRight sans GUID
    # (= tous les droits etendus, dont la reinitialisation de mot de passe).
    return guid is None or str(guid).lower() in _FORCE_CHANGE_PASSWORD_GUIDS


class ForceChangePasswordOnPrivilegedAccount(CheckPlugin):
    id = "AD-ACL-003"
    name = "Reinitialisation de mot de passe sur un compte sensible"
    version = "1.0.0"
    category = "acl"
    description = (
        "Detecte les ACE accordant le droit etendu ForceChangePassword (ou tous "
        "les droits etendus) sur un compte sensible a un principal non integre."
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
                title="Reinitialisation de mot de passe possible sur un compte sensible",
                right_label="ForceChangePassword (droit etendu)",
                impact=(
                    "Le detenteur peut definir un nouveau mot de passe pour le compte "
                    "sans connaitre l'ancien, puis s'authentifier en tant que ce compte."
                ),
                explanation=(
                    "La condition d'attaque est detectee ; elle n'est pas exploitee. "
                    "Le droit peut etre cible (GUID ForceChangePassword) ou porter sur "
                    "l'ensemble des droits etendus."
                ),
            )
            for ace in iter_dangerous_aces(data, _grants_password_reset)
            if ace.target.object_type == "user"
        ]
