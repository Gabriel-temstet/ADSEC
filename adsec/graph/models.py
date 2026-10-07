"""Modeles du graphe d'attaque interne.

Le graphe represente les objets AD deja collectes (users, groups,
computers, domaine, GPO) et les relations qui permettraient a un
attaquant de progresser de l'un a l'autre (appartenance a un groupe,
controle via ACL, delegation Kerberos...). Il n'est construit qu'a partir
de donnees deja observees : aucune requete reseau supplementaire.
"""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel

from adsec.core.models.enums import RelationConfidence


class NodeType(str, Enum):
    USER = "user"
    GROUP = "group"
    COMPUTER = "computer"
    DOMAIN = "domain"
    GPO = "gpo"
    OU = "ou"


class RelationType(str, Enum):
    MEMBER_OF = "MEMBER_OF"
    CAN_CONTROL = "CAN_CONTROL"
    OWNS = "OWNS"
    CAN_WRITE = "CAN_WRITE"
    CAN_RESET_PASSWORD = "CAN_RESET_PASSWORD"  # nosec B105 - nom de relation, pas un secret
    CAN_DCSYNC = "CAN_DCSYNC"
    APPLIES_TO = "APPLIES_TO"
    DELEGATES_TO = "DELEGATES_TO"
    TRUSTS = "TRUSTS"


class GraphNode(BaseModel):
    id: str  # DN, ou identifiant stable (fqdn de domaine, GUID de GPO)
    type: NodeType
    label: str


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relation: RelationType
    confidence: RelationConfidence
    detail: str = ""


class AttackPath(BaseModel):
    """Un chemin du noeud `source_id` vers un actif critique `target_id`."""

    engagement_id: str
    source_id: str
    target_id: str
    node_ids: list[str]
    edges: list[GraphEdge]
    length: int
    confidence: RelationConfidence  # la plus faible confiance le long du chemin
    impact_summary: str = ""

    @property
    def privilege_boundaries(self) -> int:
        """Nombre de transitions qui changent effectivement de type de
        relation (une approximation du nombre de 'frontieres' de privilege
        traversees, utile pour prioriser les chemins les plus directs)."""
        return len({e.relation for e in self.edges})
