"""Derive les limitations a afficher dans un rapport a partir de ce qui a
ete effectivement collecte pour l'engagement (aucune limitation de scan
n'est persistee individuellement a ce jour - voir ARCHITECTURE.md)."""

from __future__ import annotations

import sqlite3

from adsec.database.repositories.acl import TrustRepository
from adsec.database.repositories.directory import DirectoryRepository, GpoRepository
from adsec.database.repositories.network import DnsRepository, SmbRepository


def compute_limitations(conn: sqlite3.Connection, engagement_id: str) -> list[str]:
    limitations = []
    directory = DirectoryRepository(conn)

    if not directory.list_users(engagement_id):
        limitations.append("Aucun utilisateur collecte (acces LDAP insuffisant ou non effectue).")
    if not directory.list_all_memberships(engagement_id):
        limitations.append("Aucune appartenance a un groupe collectee.")
    if not TrustRepository(conn).list_trusts(engagement_id):
        limitations.append("Aucun trust collecte ou aucun trust present.")
    if not GpoRepository(conn).list_gpos(engagement_id):
        limitations.append("Aucune GPO collectee.")
    if not SmbRepository(conn).list_hosts(engagement_id):
        limitations.append(
            "Aucune donnee SMB collectee (profil sans categorie 'smb' ou cible injoignable)."
        )
    if not DnsRepository(conn).list_zone_checks(engagement_id):
        limitations.append(
            "Aucune donnee DNS collectee (profil sans categorie 'dns' ou cible injoignable)."
        )
    limitations.append(
        "Le contenu des GPO (GptTmpl.inf, scripts, taches planifiees) n'est pas analyse : "
        "seules les metadonnees et les permissions LDAP le sont."
    )
    limitations.append(
        "Les chemins d'attaque ne sont calcules qu'en profil 'deep' et ne retiennent que le "
        "meilleur chemin par noeud source vers chaque actif critique."
    )
    return limitations


def compute_object_counts(conn: sqlite3.Connection, engagement_id: str) -> dict[str, int]:
    from adsec.database.repositories.findings import FindingRepository
    from adsec.database.repositories.graph import AttackPathRepository

    directory = DirectoryRepository(conn)
    return {
        "users": len(directory.list_users(engagement_id)),
        "groups": len(directory.list_groups(engagement_id)),
        "computers": len(directory.list_computers(engagement_id)),
        "findings": len(FindingRepository(conn).list(engagement_id)),
        "attack_paths": len(AttackPathRepository(conn).list_all(engagement_id)),
    }
