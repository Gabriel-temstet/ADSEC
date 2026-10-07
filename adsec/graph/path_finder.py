"""Recherche des chemins les plus courts (et les plus fiables) vers chaque
actif critique.

Approche : pour chaque cible, on execute un Dijkstra sur le graphe
*inverse* en partant de la cible. La distance obtenue pour un noeud N est
alors le cout du meilleur chemin de N vers la cible dans le graphe
d'origine - ce qui donne en un seul parcours les chemins vers cette cible
depuis TOUS les noeuds, sans repeter un Dijkstra par noeud source.

Le cout d'une arete depend de sa confiance (une arete CONFIRMED coute
moins cher qu'une arete POTENTIELLE ou INFEREE), de sorte que les chemins
les plus fiables soient prefer es a distance de saut egale.
"""

from __future__ import annotations

import heapq
from collections.abc import Iterable

from adsec.core.models.enums import RelationConfidence
from adsec.graph.builder import Graph
from adsec.graph.models import AttackPath, GraphEdge, RelationType

_EDGE_COST = {
    RelationConfidence.CONFIRMED: 1.0,
    RelationConfidence.POTENTIAL: 3.0,
    RelationConfidence.INFERRED: 5.0,
}

_MAX_PATH_LENGTH = 8
_MAX_PATHS_PER_TARGET = 200


def _reverse_adjacency(graph: Graph) -> dict[str, list[GraphEdge]]:
    reverse: dict[str, list[GraphEdge]] = {}
    for edge in graph.edges:
        reverse.setdefault(edge.target_id, []).append(edge)
    return reverse


def _dijkstra_from_target(
    graph: Graph, reverse_adj: dict[str, list[GraphEdge]], target: str
) -> tuple[dict[str, float], dict[str, GraphEdge]]:
    """Dijkstra sur le graphe inverse depuis `target`. `dist[n]` = cout du
    meilleur chemin de `n` vers `target` dans le graphe original.
    `via[n]` = l'arete (dans le sens original) empruntee en dernier sur ce
    meilleur chemin, permettant de reconstruire le chemin complet."""
    dist: dict[str, float] = {target: 0.0}
    via: dict[str, GraphEdge] = {}
    heap: list[tuple[float, str]] = [(0.0, target)]
    visited: set[str] = set()

    while heap:
        d, node = heapq.heappop(heap)
        if node in visited:
            continue
        visited.add(node)
        if d > 0 and (len(via) > 0) and _path_length(via, node, target) >= _MAX_PATH_LENGTH:
            continue
        for edge in reverse_adj.get(node, []):
            # `edge` va de edge.source_id vers edge.target_id (== node) dans
            # le graphe original ; on progresse donc vers edge.source_id.
            candidate = d + _EDGE_COST[edge.confidence]
            predecessor = edge.source_id
            if candidate < dist.get(predecessor, float("inf")):
                dist[predecessor] = candidate
                via[predecessor] = edge
                heapq.heappush(heap, (candidate, predecessor))

    return dist, via


def _path_length(via: dict[str, GraphEdge], node: str, target: str) -> int:
    length = 0
    current = node
    while current != target and current in via:
        current = via[current].target_id
        length += 1
        if length > _MAX_PATH_LENGTH + 1:
            break
    return length


def _reconstruct_path(via: dict[str, GraphEdge], source: str, target: str) -> list[GraphEdge]:
    edges: list[GraphEdge] = []
    current = source
    while current != target:
        edge = via.get(current)
        if edge is None:
            return []  # ne devrait pas arriver si `dist[current]` est fini
        edges.append(edge)
        current = edge.target_id
        if len(edges) > _MAX_PATH_LENGTH:
            return []
    return edges


def find_attack_paths(graph: Graph, engagement_id: str, targets: Iterable[str]) -> list[AttackPath]:
    reverse_adj = _reverse_adjacency(graph)
    paths: list[AttackPath] = []

    for target in targets:
        if target not in graph.nodes:
            continue
        dist, via = _dijkstra_from_target(graph, reverse_adj, target)

        candidates = [(d, node) for node, d in dist.items() if node != target and d != float("inf")]
        candidates.sort(key=lambda item: item[0])

        for _cost, source in candidates[:_MAX_PATHS_PER_TARGET]:
            edges = _reconstruct_path(via, source, target)
            if not edges:
                continue
            node_ids = [source, *[e.target_id for e in edges]]
            confidences = [e.confidence for e in edges]
            worst_confidence = _worst(confidences)
            paths.append(
                AttackPath(
                    engagement_id=engagement_id,
                    source_id=source,
                    target_id=target,
                    node_ids=node_ids,
                    edges=edges,
                    length=len(edges),
                    confidence=worst_confidence,
                    impact_summary=_summarize(edges),
                )
            )

    return paths


def _worst(confidences: list[RelationConfidence]) -> RelationConfidence:
    order = [
        RelationConfidence.INFERRED,
        RelationConfidence.POTENTIAL,
        RelationConfidence.CONFIRMED,
    ]
    return min(confidences, key=order.index)


def _summarize(edges: list[GraphEdge]) -> str:
    steps = []
    for edge in edges:
        verb = {
            RelationType.MEMBER_OF: "est membre de",
            RelationType.CAN_CONTROL: "controle totalement",
            RelationType.OWNS: "est proprietaire de",
            RelationType.CAN_WRITE: "peut ecrire les proprietes de",
            RelationType.CAN_RESET_PASSWORD: "peut reinitialiser le mot de passe de",
            RelationType.CAN_DCSYNC: "peut repliquer les secrets de",
            RelationType.APPLIES_TO: "s'applique a",
            RelationType.DELEGATES_TO: "peut usurper des identites vers",
            RelationType.TRUSTS: "fait confiance a",
        }[edge.relation]
        steps.append(f"{verb} {edge.target_id}")
    return " -> ".join(steps)
