"""Couche d'adaptation entre le graphe interne (`adsec.graph`) et un format
d'export compatible avec les outils publics utilises par BloodHound.

Le modele interne (`Graph`, `GraphNode`, `GraphEdge`) ne connait jamais ce
format : cet adaptateur fait toute la traduction en un seul endroit, afin
que le reste du produit reste independant de tout format d'export externe.
Cette implementation est volontairement un sous-ensemble raisonnable
(ObjectIdentifier, Properties de base, relations) et non une copie d'une
implementation existante : la fidelite complete au schema BloodHound
(Aces imbriquees par objet, SPNTargets, sessions...) reste a completer si
le besoin se confirme.
"""

from __future__ import annotations

from dataclasses import dataclass

from adsec.core.models.ad_objects import ADComputer, ADGroup, ADUser, Domain
from adsec.core.models.gpo import GroupPolicy
from adsec.graph.builder import Graph
from adsec.graph.models import NodeType, RelationType

_BLOODHOUND_VERSION = 5

_RELATION_TO_EDGE: dict[RelationType, str] = {
    RelationType.MEMBER_OF: "MemberOf",
    RelationType.CAN_CONTROL: "GenericAll",
    RelationType.OWNS: "Owns",
    RelationType.CAN_WRITE: "GenericWrite",
    RelationType.CAN_RESET_PASSWORD: "ForceChangePassword",
    RelationType.CAN_DCSYNC: "DCSync",
    RelationType.APPLIES_TO: "GPLink",
    RelationType.DELEGATES_TO: "AllowedToDelegate",
    RelationType.TRUSTS: "TrustedBy",
}

_NODE_TYPE_TO_BH_TYPE: dict[NodeType, str] = {
    NodeType.USER: "User",
    NodeType.GROUP: "Group",
    NodeType.COMPUTER: "Computer",
    NodeType.DOMAIN: "Domain",
    NodeType.GPO: "GPO",
    NodeType.OU: "OU",
}


@dataclass
class BloodHoundExport:
    users: list[dict[str, object]]
    groups: list[dict[str, object]]
    computers: list[dict[str, object]]
    domains: list[dict[str, object]]
    gpos: list[dict[str, object]]
    relationships: list[dict[str, object]]


def _object_id(dn: str, sid: str | None) -> str:
    """BloodHound attend un identifiant stable (SID/GUID). A defaut de SID
    connu, le DN est utilise comme identifiant de repli - signale via le
    champ `adsec_identifier_is_dn` plutot que silencieusement."""
    return sid if sid else dn


def build_users(users: list[ADUser]) -> list[dict[str, object]]:
    result = []
    for user in users:
        result.append(
            {
                "ObjectIdentifier": _object_id(user.dn, user.sid),
                "adsec_identifier_is_dn": user.sid is None,
                "Properties": {
                    "name": user.sam_account_name,
                    "distinguishedname": user.dn,
                    "enabled": user.enabled,
                    "admincount": user.admin_count,
                    "dontreqpreauth": user.pre_auth_not_required,
                    "pwdneverexpires": user.password_never_expires,
                    "hasspn": bool(user.spns),
                    "serviceprincipalnames": list(user.spns),
                },
                "Aces": [],
                "IsDeleted": False,
                "IsACLProtected": False,
            }
        )
    return result


def build_groups(groups: list[ADGroup]) -> list[dict[str, object]]:
    return [
        {
            "ObjectIdentifier": _object_id(g.dn, g.sid),
            "adsec_identifier_is_dn": g.sid is None,
            "Properties": {
                "name": g.sam_account_name,
                "distinguishedname": g.dn,
                "highvalue": g.privileged,
            },
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        for g in groups
    ]


def build_computers(computers: list[ADComputer]) -> list[dict[str, object]]:
    return [
        {
            "ObjectIdentifier": _object_id(c.dn, c.sid),
            "adsec_identifier_is_dn": c.sid is None,
            "Properties": {
                "name": c.sam_account_name,
                "distinguishedname": c.dn,
                "dnshostname": c.dns_hostname,
                "operatingsystem": c.operating_system,
                "enabled": c.enabled,
                "unconstraineddelegation": c.unconstrained_delegation,
            },
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        for c in computers
    ]


def build_domains(domain: Domain) -> list[dict[str, object]]:
    return [
        {
            "ObjectIdentifier": domain.fqdn,
            "adsec_identifier_is_dn": False,
            "Properties": {
                "name": domain.fqdn,
                "distinguishedname": domain.naming_context,
                "functionallevel": domain.functional_level,
            },
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
    ]


def build_gpos(gpos: list[GroupPolicy]) -> list[dict[str, object]]:
    return [
        {
            "ObjectIdentifier": gpo.guid,
            "adsec_identifier_is_dn": False,
            "Properties": {
                "name": gpo.display_name,
                "distinguishedname": gpo.dn,
                "gpcpath": gpo.file_sys_path,
            },
            "Aces": [],
            "IsDeleted": False,
            "IsACLProtected": False,
        }
        for gpo in gpos
    ]


def build_relationships(graph: Graph) -> list[dict[str, object]]:
    relationships = []
    for edge in graph.edges:
        edge_name = _RELATION_TO_EDGE.get(edge.relation)
        if edge_name is None:
            continue
        source_node = graph.nodes.get(edge.source_id)
        target_node = graph.nodes.get(edge.target_id)
        if source_node is None or target_node is None:
            continue
        relationships.append(
            {
                "source": edge.source_id,
                "sourcetype": _NODE_TYPE_TO_BH_TYPE[source_node.type],
                "target": edge.target_id,
                "targettype": _NODE_TYPE_TO_BH_TYPE[target_node.type],
                "relationtype": edge_name,
                "isacl": edge.relation
                in (
                    RelationType.CAN_CONTROL,
                    RelationType.OWNS,
                    RelationType.CAN_WRITE,
                    RelationType.CAN_RESET_PASSWORD,
                    RelationType.CAN_DCSYNC,
                ),
                "confidence": edge.confidence.value,
            }
        )
    return relationships


def build_export(
    *,
    graph: Graph,
    users: list[ADUser],
    groups: list[ADGroup],
    computers: list[ADComputer],
    domain: Domain,
    gpos: list[GroupPolicy],
) -> BloodHoundExport:
    return BloodHoundExport(
        users=build_users(users),
        groups=build_groups(groups),
        computers=build_computers(computers),
        domains=build_domains(domain),
        gpos=build_gpos(gpos),
        relationships=build_relationships(graph),
    )
