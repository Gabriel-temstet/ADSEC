"""Normalisation des resultats bruts du LdapCollector vers les modeles
pydantic du moteur (`ADUser`, `ADGroup`, `ADComputer`, `OrganizationalUnit`,
`GroupMembership`). Etape distincte de la collecte, conformement au
pipeline Discovery -> Collection -> Normalization -> ...

La construction passe par `model_validate` : un champ de type inattendu
leve une `ValidationError` explicite au lieu de corrompre silencieusement
les donnees persistees."""

from __future__ import annotations

from dataclasses import dataclass, field

from adsec.collectors.base import CollectionResult
from adsec.collectors.ldap.attributes import parse_gplink
from adsec.core.models.acl import Acl, Permission, Trust
from adsec.core.models.ad_objects import (
    WELL_KNOWN_PRIVILEGED_GROUPS,
    ADComputer,
    ADGroup,
    ADUser,
    GroupMembership,
    OrganizationalUnit,
)
from adsec.core.models.gpo import GpoLink, GroupPolicy


@dataclass
class NormalizedDirectory:
    ous: list[OrganizationalUnit] = field(default_factory=list)
    users: list[ADUser] = field(default_factory=list)
    groups: list[ADGroup] = field(default_factory=list)
    computers: list[ADComputer] = field(default_factory=list)
    memberships: list[GroupMembership] = field(default_factory=list)
    acls: list[Acl] = field(default_factory=list)
    trusts: list[Trust] = field(default_factory=list)
    gpos: list[GroupPolicy] = field(default_factory=list)


def _with_ids(row: dict[str, object], engagement_id: str, domain_id: str) -> dict[str, object]:
    return {**row, "engagement_id": engagement_id, "domain_id": domain_id}


def normalize_ldap_collection(
    engagement_id: str, domain_id: str, result: CollectionResult
) -> NormalizedDirectory:
    normalized = NormalizedDirectory()
    dn_to_type: dict[str, str] = {}

    for raw_ou in result.objects.get("ous", []):
        ou_row = _with_ids(raw_ou, engagement_id, domain_id)
        ou_row["gplinks"] = list(raw_ou.get("gplinks") or [])  # type: ignore[call-overload]
        normalized.ous.append(OrganizationalUnit.model_validate(ou_row))

    for raw_user in result.objects.get("users", []):
        user = ADUser.model_validate(_with_ids(raw_user, engagement_id, domain_id))
        dn_to_type[user.dn.lower()] = "user"
        normalized.users.append(user)

    for raw_computer in result.objects.get("computers", []):
        computer = ADComputer.model_validate(_with_ids(raw_computer, engagement_id, domain_id))
        dn_to_type[computer.dn.lower()] = "computer"
        normalized.computers.append(computer)

    raw_groups = result.objects.get("groups", [])
    groups: list[tuple[ADGroup, list[str]]] = []
    for raw_group in raw_groups:
        members_value = raw_group.get("members") or []
        members = [str(m) for m in members_value] if isinstance(members_value, list) else []
        row = {
            k: v
            for k, v in _with_ids(raw_group, engagement_id, domain_id).items()
            if k != "members"
        }
        group = ADGroup.model_validate(row)
        group.privileged = group.sam_account_name.lower() in WELL_KNOWN_PRIVILEGED_GROUPS
        dn_to_type[group.dn.lower()] = "group"
        groups.append((group, members))

    for group, members in groups:
        normalized.groups.append(group)
        for member_dn in members:
            normalized.memberships.append(
                GroupMembership(
                    engagement_id=engagement_id,
                    group_dn=group.dn,
                    member_dn=member_dn,
                    member_type=dn_to_type.get(member_dn.lower(), "unknown"),
                    nested=False,
                )
            )

    for raw_acl in result.objects.get("acls", []):
        raw_permissions = raw_acl.get("permissions")
        permissions = (
            [Permission.model_validate(p) for p in raw_permissions if isinstance(p, dict)]
            if isinstance(raw_permissions, list)
            else []
        )
        acl_row = {k: v for k, v in raw_acl.items() if k != "permissions"}
        normalized.acls.append(
            Acl.model_validate(
                {**acl_row, "engagement_id": engagement_id, "permissions": permissions}
            )
        )

    for raw_trust in result.objects.get("trusts", []):
        normalized.trusts.append(
            Trust.model_validate(_with_ids(raw_trust, engagement_id, domain_id))
        )

    normalized.gpos = _build_gpos(engagement_id, domain_id, result, normalized.ous)

    return normalized


def _build_gpos(
    engagement_id: str,
    domain_id: str,
    result: CollectionResult,
    ous: list[OrganizationalUnit],
) -> list[GroupPolicy]:
    """Construit les GPO et calcule leurs liens a partir des attributs
    gPLink des OUs et de la racine du domaine."""
    links_by_guid: dict[str, list[GpoLink]] = {}

    def register(target_dn: str, gplinks: list[str]) -> None:
        for raw in gplinks:
            for link in parse_gplink(raw):
                links_by_guid.setdefault(link.guid, []).append(
                    GpoLink(target_dn=target_dn, enabled=not link.disabled, enforced=link.enforced)
                )

    for ou in ous:
        register(ou.dn, ou.gplinks)
    for root in result.objects.get("domain_root", []):
        raw_links = root.get("gplinks")
        if isinstance(raw_links, list):
            register(str(root["dn"]), [str(x) for x in raw_links])

    gpos: list[GroupPolicy] = []
    for raw_gpo in result.objects.get("gpos", []):
        row = _with_ids(raw_gpo, engagement_id, domain_id)
        row["links"] = links_by_guid.get(str(raw_gpo["guid"]).upper(), [])
        gpos.append(GroupPolicy.model_validate(row))
    return gpos
