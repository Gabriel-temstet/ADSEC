"""Repository pour les ACL (permissions) et les trusts."""

from __future__ import annotations

import json
import sqlite3

from adsec.core.models.acl import Acl, Permission, Trust


class AclRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert_acl(self, acl: Acl) -> Acl:
        row = self._conn.execute(
            "SELECT id FROM acls WHERE engagement_id = ? AND object_dn = ?;",
            (acl.engagement_id, acl.object_dn),
        ).fetchone()
        if row is not None:
            acl = acl.model_copy(update={"id": row["id"]})
            self._conn.execute("DELETE FROM permissions WHERE acl_id = ?;", (acl.id,))

        self._conn.execute(
            "INSERT INTO acls (id, engagement_id, object_dn, object_type, owner_sid) "
            "VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " object_type = excluded.object_type, owner_sid = excluded.owner_sid;",
            (acl.id, acl.engagement_id, acl.object_dn, acl.object_type, acl.owner_sid),
        )
        for perm in acl.permissions:
            self._conn.execute(
                "INSERT INTO permissions "
                "(id, engagement_id, acl_id, trustee_sid, ace_type, rights_mask, "
                " rights_json, object_type_guid, inherited) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    perm.id,
                    acl.engagement_id,
                    acl.id,
                    perm.trustee_sid,
                    perm.ace_type,
                    perm.rights_mask,
                    json.dumps(perm.rights),
                    perm.object_type_guid,
                    int(perm.inherited),
                ),
            )
        return acl

    def list_acls(self, engagement_id: str) -> list[Acl]:
        acl_rows = self._conn.execute(
            "SELECT * FROM acls WHERE engagement_id = ? ORDER BY object_dn;",
            (engagement_id,),
        ).fetchall()
        acls = []
        for row in acl_rows:
            perm_rows = self._conn.execute(
                "SELECT * FROM permissions WHERE acl_id = ?;", (row["id"],)
            ).fetchall()
            permissions = [
                Permission(
                    id=p["id"],
                    trustee_sid=p["trustee_sid"],
                    ace_type=p["ace_type"],
                    rights_mask=p["rights_mask"],
                    rights=json.loads(p["rights_json"]),
                    object_type_guid=p["object_type_guid"],
                    inherited=bool(p["inherited"]),
                )
                for p in perm_rows
            ]
            acls.append(
                Acl(
                    id=row["id"],
                    engagement_id=row["engagement_id"],
                    object_dn=row["object_dn"],
                    object_type=row["object_type"],
                    owner_sid=row["owner_sid"],
                    permissions=permissions,
                )
            )
        return acls


class TrustRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert_trust(self, trust: Trust) -> Trust:
        row = self._conn.execute(
            "SELECT id FROM trusts WHERE engagement_id = ? AND trust_partner = ?;",
            (trust.engagement_id, trust.trust_partner),
        ).fetchone()
        if row is not None:
            trust = trust.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO trusts "
            "(id, engagement_id, domain_id, trust_partner, direction, trust_type, "
            " transitive, sid_filtering, raw_attrs_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " direction = excluded.direction, trust_type = excluded.trust_type, "
            " transitive = excluded.transitive, sid_filtering = excluded.sid_filtering, "
            " raw_attrs_json = excluded.raw_attrs_json;",
            (
                trust.id,
                trust.engagement_id,
                trust.domain_id,
                trust.trust_partner,
                trust.direction,
                trust.trust_type,
                int(trust.transitive),
                int(trust.sid_filtering),
                json.dumps(trust.raw_attrs),
            ),
        )
        return trust

    def list_trusts(self, engagement_id: str) -> list[Trust]:
        rows = self._conn.execute(
            "SELECT * FROM trusts WHERE engagement_id = ? ORDER BY trust_partner;",
            (engagement_id,),
        ).fetchall()
        return [
            Trust(
                id=r["id"],
                engagement_id=r["engagement_id"],
                domain_id=r["domain_id"],
                trust_partner=r["trust_partner"],
                direction=r["direction"],
                trust_type=r["trust_type"],
                transitive=bool(r["transitive"]),
                sid_filtering=bool(r["sid_filtering"]),
                raw_attrs=json.loads(r["raw_attrs_json"]),
            )
            for r in rows
        ]
