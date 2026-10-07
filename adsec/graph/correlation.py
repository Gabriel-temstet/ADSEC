"""Correlation entre findings et chemins d'attaque.

Un finding est correle a un chemin lorsque ce chemin DEMARRE exactement
par la relation que ce finding decrit, depuis le meme principal. Par
exemple, un finding `AD-ACL-001` (GenericAll) dont le principal est le SID
X est correle a tout chemin d'attaque dont le premier saut est
`X -CAN_CONTROL-> ...`. C'est une correspondance structurelle exacte, pas
une heuristique approximative : si elle ne matche pas, le finding reste
simplement non correle (plutot que de forcer un lien incertain).
"""

from __future__ import annotations

from dataclasses import dataclass

from adsec.graph.models import AttackPath, RelationType
from adsec.rules.base import Finding

# Un rule_id de finding ACL/GPO correspond exactement a UNE relation de
# graphe : c'est la meme condition (meme ACE) qui produit les deux.
_RULE_TO_RELATION: dict[str, RelationType] = {
    "AD-ACL-001": RelationType.CAN_CONTROL,
    "AD-ACL-002": RelationType.CAN_CONTROL,
    "AD-ACL-004": RelationType.CAN_WRITE,
    "AD-ACL-003": RelationType.CAN_RESET_PASSWORD,
    "AD-ACL-005": RelationType.CAN_DCSYNC,
    "AD-GPO-001": RelationType.CAN_WRITE,
}


@dataclass(frozen=True)
class Correlation:
    finding_id: str
    path_index: int  # index dans la liste `paths` passee a `correlate`


def _resolve_node(principal: str, sid_to_dn: dict[str, str]) -> str:
    """Un principal de finding est soit un SID (ACL/Kerberos), soit deja un
    DN/identifiant de noeud (GPO, trust, SMB, DNS)."""
    if principal.startswith("S-1-"):
        return sid_to_dn.get(principal, principal)
    return principal


def correlate(
    findings: list[tuple[str, Finding]],
    paths: list[AttackPath],
    sid_to_dn: dict[str, str],
) -> list[Correlation]:
    """Associe chaque finding aux chemins dont le premier saut correspond
    exactement a la condition qu'il decrit : meme principal source, meme
    relation, ET meme objet cible (sauf pour AD-ACL-005/DCSync, dont la
    cible est par construction toujours le domaine).

    La verification de la cible du premier saut est essentielle : deux
    arretes peuvent partir du meme principal avec la meme relation vers
    des objets differents (ex: un groupe de support avec GenericAll sur
    plusieurs comptes) - sans elle, un finding pourrait se retrouver lie a
    un chemin qui n'emprunte pas du tout l'ACE qu'il decrit.
    """
    correlations: list[Correlation] = []

    for finding_id, finding in findings:
        relation = _RULE_TO_RELATION.get(finding.rule_id)
        if relation is None or not finding.principal:
            continue
        source_node = _resolve_node(finding.principal, sid_to_dn)
        domain_wide = finding.rule_id == "AD-ACL-005"
        affected = set(finding.affected_assets)

        for index, path in enumerate(paths):
            if not path.edges:
                continue
            first_edge = path.edges[0]
            if path.source_id != source_node or first_edge.relation != relation:
                continue
            if not domain_wide and first_edge.target_id not in affected:
                continue
            correlations.append(Correlation(finding_id=finding_id, path_index=index))

    return correlations
