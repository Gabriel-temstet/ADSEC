"""Construit le graphe interne a partir des donnees deja persistees pour un
engagement (users, groups, computers, group_memberships, acls, gpos,
trusts). Aucune connexion reseau : le graphe est une relecture des
observations existantes."""

from __future__ import annotations

from dataclasses import dataclass, field

from adsec.collectors.ldap.attributes import UAC_SERVER_TRUST_ACCOUNT
from adsec.collectors.ldap.rights import (
    RIGHT_DS_CONTROL_ACCESS,
    RIGHT_WRITE_OWNER,
    has_right,
    is_full_control,
    is_generic_write,
)
from adsec.core.models.ad_objects import WELL_KNOWN_PRIVILEGED_GROUPS
from adsec.core.models.enums import RelationConfidence
from adsec.graph.models import GraphEdge, GraphNode, NodeType, RelationType
from adsec.rules.acl.well_known_sids import is_well_known_safe_trustee

_DS_REPL_GET_CHANGES = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
_DS_REPL_GET_CHANGES_ALL = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"


@dataclass
class Graph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)

    def add_node(self, node_id: str, node_type: NodeType, label: str) -> None:
        if node_id not in self.nodes:
            self.nodes[node_id] = GraphNode(id=node_id, type=node_type, label=label)

    def add_edge(self, edge: GraphEdge) -> None:
        if edge.source_id == edge.target_id:
            return  # une auto-reference n'est jamais un chemin utile
        self.edges.append(edge)

    def adjacency(self) -> dict[str, list[GraphEdge]]:
        adj: dict[str, list[GraphEdge]] = {}
        for edge in self.edges:
            adj.setdefault(edge.source_id, []).append(edge)
        return adj


def build_sid_to_dn(
    users: list[dict[str, object]],
    groups: list[dict[str, object]],
    computers: list[dict[str, object]],
) -> dict[str, str]:
    """Construit la table de resolution SID -> DN, partagee entre la
    construction du graphe et la correlation findings/chemins d'attaque."""
    sid_to_dn: dict[str, str] = {}
    for row in (*users, *groups, *computers):
        if row.get("sid"):
            sid_to_dn[str(row["sid"])] = str(row["dn"])
    return sid_to_dn


def build_graph(
    *,
    users: list[dict[str, object]],
    groups: list[dict[str, object]],
    computers: list[dict[str, object]],
    memberships: list[dict[str, object]],
    acls: list[dict[str, object]],
    gpos: list[dict[str, object]],
    domain_fqdn: str,
) -> Graph:
    graph = Graph()
    sid_to_dn = build_sid_to_dn(users, groups, computers)

    graph.add_node(domain_fqdn, NodeType.DOMAIN, domain_fqdn)

    for row in users:
        graph.add_node(str(row["dn"]), NodeType.USER, str(row["sam_account_name"]))

    for row in groups:
        graph.add_node(str(row["dn"]), NodeType.GROUP, str(row["sam_account_name"]))

    for row in computers:
        graph.add_node(str(row["dn"]), NodeType.COMPUTER, str(row["sam_account_name"]))

    for row in gpos:
        dn = str(row["dn"])
        graph.add_node(dn, NodeType.GPO, str(row["display_name"]))

    _add_membership_edges(graph, memberships)
    _add_acl_edges(graph, acls, sid_to_dn, domain_fqdn)
    _add_gpo_edges(graph, gpos)

    return graph


def _add_membership_edges(graph: Graph, memberships: list[dict[str, object]]) -> None:
    for row in memberships:
        member_dn = str(row["member_dn"])
        group_dn = str(row["group_dn"])
        if member_dn not in graph.nodes or group_dn not in graph.nodes:
            continue  # membre externe/non resolu (ex: foreignSecurityPrincipal)
        graph.add_edge(
            GraphEdge(
                source_id=member_dn,
                target_id=group_dn,
                relation=RelationType.MEMBER_OF,
                confidence=RelationConfidence.CONFIRMED,
                detail="appartenance directe observee",
            )
        )


def _resolve_trustee(sid: str, sid_to_dn: dict[str, str]) -> str | None:
    return sid_to_dn.get(sid)


def _add_acl_edges(
    graph: Graph,
    acls: list[dict[str, object]],
    sid_to_dn: dict[str, str],
    domain_fqdn: str,
) -> None:
    for acl in acls:
        object_dn = str(acl["object_dn"])
        object_type = str(acl.get("object_type"))
        target_node_id = domain_fqdn if object_type == "domain" else object_dn
        if target_node_id not in graph.nodes:
            continue

        permissions = acl.get("permissions")
        dcsync_tokens: dict[str, set[str]] = {}

        for perm in permissions if isinstance(permissions, list) else []:
            if not isinstance(perm, dict) or perm.get("ace_type") not in (
                "ALLOWED",
                "ALLOWED_OBJECT",
            ):
                continue
            sid = str(perm["trustee_sid"])
            if is_well_known_safe_trustee(sid):
                continue
            source_dn = _resolve_trustee(sid, sid_to_dn)
            if source_dn is None or source_dn not in graph.nodes:
                continue

            mask = int(str(perm["rights_mask"]))
            guid = str(perm["object_type_guid"]).lower() if perm.get("object_type_guid") else None

            if object_type == "domain" and has_right(mask, RIGHT_DS_CONTROL_ACCESS):
                if guid == _DS_REPL_GET_CHANGES:
                    dcsync_tokens.setdefault(sid, set()).add("changes")
                elif guid == _DS_REPL_GET_CHANGES_ALL:
                    dcsync_tokens.setdefault(sid, set()).add("changes_all")
                elif guid is None:
                    dcsync_tokens.setdefault(sid, set()).add("changes")
                    dcsync_tokens.setdefault(sid, set()).add("changes_all")
                continue

            if is_full_control(mask):
                graph.add_edge(
                    GraphEdge(
                        source_id=source_dn,
                        target_id=target_node_id,
                        relation=RelationType.CAN_CONTROL,
                        confidence=RelationConfidence.CONFIRMED,
                        detail="GenericAll",
                    )
                )
            elif has_right(mask, RIGHT_WRITE_OWNER):
                graph.add_edge(
                    GraphEdge(
                        source_id=source_dn,
                        target_id=target_node_id,
                        relation=RelationType.OWNS,
                        confidence=RelationConfidence.CONFIRMED,
                        detail="WriteOwner",
                    )
                )
            elif is_generic_write(mask, guid):
                graph.add_edge(
                    GraphEdge(
                        source_id=source_dn,
                        target_id=target_node_id,
                        relation=RelationType.CAN_WRITE,
                        confidence=RelationConfidence.CONFIRMED,
                        detail="GenericWrite",
                    )
                )
            elif (
                has_right(mask, RIGHT_DS_CONTROL_ACCESS)
                and guid == "00299570-246d-11d0-a768-00aa006e0529"
            ):
                graph.add_edge(
                    GraphEdge(
                        source_id=source_dn,
                        target_id=target_node_id,
                        relation=RelationType.CAN_RESET_PASSWORD,
                        confidence=RelationConfidence.CONFIRMED,
                        detail="ForceChangePassword",
                    )
                )

        for sid, tokens in dcsync_tokens.items():
            source_dn = _resolve_trustee(sid, sid_to_dn)
            if source_dn is None or source_dn not in graph.nodes:
                continue
            complete = {"changes", "changes_all"} <= tokens
            graph.add_edge(
                GraphEdge(
                    source_id=source_dn,
                    target_id=domain_fqdn,
                    relation=RelationType.CAN_DCSYNC,
                    confidence=(
                        RelationConfidence.CONFIRMED if complete else RelationConfidence.POTENTIAL
                    ),
                    detail="droits de replication (DCSync)",
                )
            )


def _add_gpo_edges(graph: Graph, gpos: list[dict[str, object]]) -> None:
    """Ajoute uniquement les liens GPO -> perimetre applique (APPLIES_TO).

    Les ACE 'qui peut ecrire cette GPO' sont deja couvertes par
    `_add_acl_edges` (l'ACL de la GPO est incluse dans `acls`, avec
    `object_type == "gpo"` et `object_dn == gpo.dn`)."""
    for gpo in gpos:
        dn = str(gpo["dn"])
        links = gpo.get("links")
        for link in links if isinstance(links, list) else []:
            if not isinstance(link, dict) or not link.get("enabled", True):
                continue
            target_dn = str(link["target_dn"])
            if target_dn not in graph.nodes:
                graph.add_node(target_dn, NodeType.OU, target_dn)
            graph.add_edge(
                GraphEdge(
                    source_id=dn,
                    target_id=target_dn,
                    relation=RelationType.APPLIES_TO,
                    confidence=RelationConfidence.CONFIRMED,
                    detail="lien de GPO",
                )
            )


def is_privileged_group_row(row: dict[str, object]) -> bool:
    return str(row.get("sam_account_name", "")).lower() in WELL_KNOWN_PRIVILEGED_GROUPS


def is_domain_controller_row(row: dict[str, object]) -> bool:
    raw = row.get("raw_attrs")
    uac = raw.get("userAccountControl") if isinstance(raw, dict) else None
    return isinstance(uac, int) and bool(uac & UAC_SERVER_TRUST_ACCOUNT)


def critical_targets(
    groups: list[dict[str, object]], computers: list[dict[str, object]], domain_fqdn: str
) -> list[str]:
    """Identifie les noeuds 'jackpot' : groupes integres a privileges,
    controleurs de domaine, et le domaine lui-meme (pour la portee DCSync)."""
    targets = [str(g["dn"]) for g in groups if is_privileged_group_row(g)]
    targets += [str(c["dn"]) for c in computers if is_domain_controller_row(c)]
    targets.append(domain_fqdn)
    return targets
