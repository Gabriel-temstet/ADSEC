"""Repository pour la topologie AD : forets, domaines, sites, DC."""

from __future__ import annotations

import json
import sqlite3

from adsec.core.models.ad_objects import Domain, DomainController, Forest, Site


class TopologyRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert_forest(self, forest: Forest) -> Forest:
        self._conn.execute(
            "INSERT INTO forests (id, engagement_id, name, functional_level) "
            "VALUES (?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET functional_level = excluded.functional_level;",
            (forest.id, forest.engagement_id, forest.name, forest.functional_level),
        )
        return forest

    def upsert_domain(self, domain: Domain) -> Domain:
        row = self._conn.execute(
            "SELECT id FROM domains WHERE engagement_id = ? AND fqdn = ?;",
            (domain.engagement_id, domain.fqdn),
        ).fetchone()
        if row is not None:
            domain = domain.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO domains "
            "(id, engagement_id, forest_id, fqdn, netbios, functional_level, naming_context) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " forest_id = excluded.forest_id, netbios = excluded.netbios, "
            " functional_level = excluded.functional_level, "
            " naming_context = excluded.naming_context;",
            (
                domain.id,
                domain.engagement_id,
                domain.forest_id,
                domain.fqdn,
                domain.netbios,
                domain.functional_level,
                domain.naming_context,
            ),
        )
        return domain

    def get_domain_by_fqdn(self, engagement_id: str, fqdn: str) -> Domain | None:
        row = self._conn.execute(
            "SELECT * FROM domains WHERE engagement_id = ? AND fqdn = ?;",
            (engagement_id, fqdn),
        ).fetchone()
        return self._domain_from_row(row) if row else None

    def list_domains(self, engagement_id: str) -> list[Domain]:
        rows = self._conn.execute(
            "SELECT * FROM domains WHERE engagement_id = ? ORDER BY fqdn;",
            (engagement_id,),
        ).fetchall()
        return [self._domain_from_row(r) for r in rows]

    def upsert_site(self, site: Site) -> Site:
        self._conn.execute(
            "INSERT INTO sites (id, engagement_id, domain_id, name) VALUES (?, ?, ?, ?);",
            (site.id, site.engagement_id, site.domain_id, site.name),
        )
        return site

    def upsert_domain_controller(self, dc: DomainController) -> DomainController:
        row = self._conn.execute(
            "SELECT id FROM domain_controllers WHERE engagement_id = ? AND hostname = ?;",
            (dc.engagement_id, dc.hostname),
        ).fetchone()
        if row is not None:
            dc = dc.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO domain_controllers "
            "(id, engagement_id, domain_id, hostname, ip, is_global_catalog, "
            " os_version, fsmo_roles_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " ip = excluded.ip, is_global_catalog = excluded.is_global_catalog, "
            " os_version = excluded.os_version, fsmo_roles_json = excluded.fsmo_roles_json;",
            (
                dc.id,
                dc.engagement_id,
                dc.domain_id,
                dc.hostname,
                dc.ip,
                int(dc.is_global_catalog),
                dc.os_version,
                json.dumps(dc.fsmo_roles),
            ),
        )
        return dc

    def list_domain_controllers(self, engagement_id: str) -> list[DomainController]:
        rows = self._conn.execute(
            "SELECT * FROM domain_controllers WHERE engagement_id = ? ORDER BY hostname;",
            (engagement_id,),
        ).fetchall()
        return [
            DomainController(
                id=r["id"],
                engagement_id=r["engagement_id"],
                domain_id=r["domain_id"],
                hostname=r["hostname"],
                ip=r["ip"],
                is_global_catalog=bool(r["is_global_catalog"]),
                os_version=r["os_version"],
                fsmo_roles=json.loads(r["fsmo_roles_json"]),
            )
            for r in rows
        ]

    @staticmethod
    def _domain_from_row(row: sqlite3.Row) -> Domain:
        return Domain(
            id=row["id"],
            engagement_id=row["engagement_id"],
            forest_id=row["forest_id"],
            fqdn=row["fqdn"],
            netbios=row["netbios"],
            functional_level=row["functional_level"],
            naming_context=row["naming_context"],
        )
