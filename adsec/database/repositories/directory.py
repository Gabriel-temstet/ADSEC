"""Repository pour les objets annuaire collectes via LDAP.

Toutes les operations d'ecriture sont des upserts sur (engagement_id, dn) :
un re-scan du meme engagement met a jour les objets existants plutot que
d'en creer des doublons, ce qui prepare le terrain pour le `diff` de
scans (Phase 7) sans le necessiter des maintenant.
"""

from __future__ import annotations

import json
import sqlite3

from adsec.core.models.ad_objects import (
    ADComputer,
    ADGroup,
    ADUser,
    GroupMembership,
    OrganizationalUnit,
)
from adsec.core.models.gpo import GpoLink, GroupPolicy


class DirectoryRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    # -- Organizational Units -----------------------------------------

    def upsert_ou(self, ou: OrganizationalUnit) -> OrganizationalUnit:
        row = self._conn.execute(
            "SELECT id FROM ous WHERE engagement_id = ? AND dn = ?;",
            (ou.engagement_id, ou.dn),
        ).fetchone()
        if row is not None:
            ou = ou.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO ous (id, engagement_id, domain_id, dn, name, parent_dn, gplink_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " name = excluded.name, parent_dn = excluded.parent_dn, "
            " gplink_json = excluded.gplink_json;",
            (
                ou.id,
                ou.engagement_id,
                ou.domain_id,
                ou.dn,
                ou.name,
                ou.parent_dn,
                json.dumps(ou.gplinks),
            ),
        )
        return ou

    def list_ous(self, engagement_id: str) -> list[OrganizationalUnit]:
        rows = self._conn.execute(
            "SELECT * FROM ous WHERE engagement_id = ? ORDER BY dn;", (engagement_id,)
        ).fetchall()
        return [
            OrganizationalUnit(
                id=r["id"],
                engagement_id=r["engagement_id"],
                domain_id=r["domain_id"],
                dn=r["dn"],
                name=r["name"],
                parent_dn=r["parent_dn"],
                gplinks=json.loads(r["gplink_json"]),
            )
            for r in rows
        ]

    # -- Users ----------------------------------------------------------

    def upsert_user(self, user: ADUser) -> ADUser:
        row = self._conn.execute(
            "SELECT id FROM users WHERE engagement_id = ? AND dn = ?;",
            (user.engagement_id, user.dn),
        ).fetchone()
        if row is not None:
            user = user.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO users "
            "(id, engagement_id, domain_id, dn, sam_account_name, sid, upn, enabled, "
            " admin_count, password_never_expires, pre_auth_not_required, last_logon, "
            " pwd_last_set, spns_json, raw_attrs_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " sam_account_name = excluded.sam_account_name, sid = excluded.sid, "
            " upn = excluded.upn, enabled = excluded.enabled, "
            " admin_count = excluded.admin_count, "
            " password_never_expires = excluded.password_never_expires, "
            " pre_auth_not_required = excluded.pre_auth_not_required, "
            " last_logon = excluded.last_logon, pwd_last_set = excluded.pwd_last_set, "
            " spns_json = excluded.spns_json, raw_attrs_json = excluded.raw_attrs_json;",
            (
                user.id,
                user.engagement_id,
                user.domain_id,
                user.dn,
                user.sam_account_name,
                user.sid,
                user.upn,
                int(user.enabled),
                int(user.admin_count),
                int(user.password_never_expires),
                int(user.pre_auth_not_required),
                user.last_logon,
                user.pwd_last_set,
                json.dumps(user.spns),
                json.dumps(user.raw_attrs),
            ),
        )
        return user

    def list_users(self, engagement_id: str) -> list[ADUser]:
        rows = self._conn.execute(
            "SELECT * FROM users WHERE engagement_id = ? ORDER BY sam_account_name;",
            (engagement_id,),
        ).fetchall()
        return [self._user_from_row(r) for r in rows]

    @staticmethod
    def _user_from_row(row: sqlite3.Row) -> ADUser:
        return ADUser(
            id=row["id"],
            engagement_id=row["engagement_id"],
            domain_id=row["domain_id"],
            dn=row["dn"],
            sam_account_name=row["sam_account_name"],
            sid=row["sid"],
            upn=row["upn"],
            enabled=bool(row["enabled"]),
            admin_count=bool(row["admin_count"]),
            password_never_expires=bool(row["password_never_expires"]),
            pre_auth_not_required=bool(row["pre_auth_not_required"]),
            last_logon=row["last_logon"],
            pwd_last_set=row["pwd_last_set"],
            spns=json.loads(row["spns_json"]),
            raw_attrs=json.loads(row["raw_attrs_json"]),
        )

    # -- Groups -----------------------------------------------------------

    def upsert_group(self, group: ADGroup) -> ADGroup:
        row = self._conn.execute(
            "SELECT id FROM groups WHERE engagement_id = ? AND dn = ?;",
            (group.engagement_id, group.dn),
        ).fetchone()
        if row is not None:
            group = group.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO groups "
            "(id, engagement_id, domain_id, dn, sam_account_name, sid, privileged, raw_attrs_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " sam_account_name = excluded.sam_account_name, sid = excluded.sid, "
            " privileged = excluded.privileged, raw_attrs_json = excluded.raw_attrs_json;",
            (
                group.id,
                group.engagement_id,
                group.domain_id,
                group.dn,
                group.sam_account_name,
                group.sid,
                int(group.privileged),
                json.dumps(group.raw_attrs),
            ),
        )
        return group

    def list_groups(self, engagement_id: str) -> list[ADGroup]:
        rows = self._conn.execute(
            "SELECT * FROM groups WHERE engagement_id = ? ORDER BY sam_account_name;",
            (engagement_id,),
        ).fetchall()
        return [
            ADGroup(
                id=r["id"],
                engagement_id=r["engagement_id"],
                domain_id=r["domain_id"],
                dn=r["dn"],
                sam_account_name=r["sam_account_name"],
                sid=r["sid"],
                privileged=bool(r["privileged"]),
                raw_attrs=json.loads(r["raw_attrs_json"]),
            )
            for r in rows
        ]

    # -- Group memberships --------------------------------------------

    def upsert_membership(self, membership: GroupMembership) -> GroupMembership:
        self._conn.execute(
            "INSERT INTO group_memberships "
            "(id, engagement_id, group_dn, member_dn, member_type, nested) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(engagement_id, group_dn, member_dn) DO UPDATE SET "
            " member_type = excluded.member_type, nested = excluded.nested;",
            (
                membership.id,
                membership.engagement_id,
                membership.group_dn,
                membership.member_dn,
                membership.member_type,
                int(membership.nested),
            ),
        )
        return membership

    def list_memberships_for_group(
        self, engagement_id: str, group_dn: str
    ) -> list[GroupMembership]:
        rows = self._conn.execute(
            "SELECT * FROM group_memberships WHERE engagement_id = ? AND group_dn = ?;",
            (engagement_id, group_dn),
        ).fetchall()
        return [self._membership_from_row(r) for r in rows]

    def list_all_memberships(self, engagement_id: str) -> list[GroupMembership]:
        rows = self._conn.execute(
            "SELECT * FROM group_memberships WHERE engagement_id = ?;", (engagement_id,)
        ).fetchall()
        return [self._membership_from_row(r) for r in rows]

    @staticmethod
    def _membership_from_row(row: sqlite3.Row) -> GroupMembership:
        return GroupMembership(
            id=row["id"],
            engagement_id=row["engagement_id"],
            group_dn=row["group_dn"],
            member_dn=row["member_dn"],
            member_type=row["member_type"],
            nested=bool(row["nested"]),
        )

    # -- Computers --------------------------------------------------------

    def upsert_computer(self, computer: ADComputer) -> ADComputer:
        row = self._conn.execute(
            "SELECT id FROM computers WHERE engagement_id = ? AND dn = ?;",
            (computer.engagement_id, computer.dn),
        ).fetchone()
        if row is not None:
            computer = computer.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO computers "
            "(id, engagement_id, domain_id, dn, sam_account_name, sid, dns_hostname, "
            " operating_system, enabled, unconstrained_delegation, raw_attrs_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " sam_account_name = excluded.sam_account_name, sid = excluded.sid, "
            " dns_hostname = excluded.dns_hostname, "
            " operating_system = excluded.operating_system, enabled = excluded.enabled, "
            " unconstrained_delegation = excluded.unconstrained_delegation, "
            " raw_attrs_json = excluded.raw_attrs_json;",
            (
                computer.id,
                computer.engagement_id,
                computer.domain_id,
                computer.dn,
                computer.sam_account_name,
                computer.sid,
                computer.dns_hostname,
                computer.operating_system,
                int(computer.enabled),
                int(computer.unconstrained_delegation),
                json.dumps(computer.raw_attrs),
            ),
        )
        return computer

    def list_computers(self, engagement_id: str) -> list[ADComputer]:
        rows = self._conn.execute(
            "SELECT * FROM computers WHERE engagement_id = ? ORDER BY sam_account_name;",
            (engagement_id,),
        ).fetchall()
        return [
            ADComputer(
                id=r["id"],
                engagement_id=r["engagement_id"],
                domain_id=r["domain_id"],
                dn=r["dn"],
                sam_account_name=r["sam_account_name"],
                sid=r["sid"],
                dns_hostname=r["dns_hostname"],
                operating_system=r["operating_system"],
                enabled=bool(r["enabled"]),
                unconstrained_delegation=bool(r["unconstrained_delegation"]),
                raw_attrs=json.loads(r["raw_attrs_json"]),
            )
            for r in rows
        ]


class GpoRepository:
    """Repository des GPO (metadonnees et liens)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert_gpo(self, gpo: GroupPolicy) -> GroupPolicy:
        row = self._conn.execute(
            "SELECT id FROM gpos WHERE engagement_id = ? AND guid = ?;",
            (gpo.engagement_id, gpo.guid),
        ).fetchone()
        if row is not None:
            gpo = gpo.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO gpos (id, engagement_id, domain_id, guid, dn, display_name, "
            " file_sys_path, version_number, flags, links_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " dn = excluded.dn, display_name = excluded.display_name, "
            " file_sys_path = excluded.file_sys_path, "
            " version_number = excluded.version_number, flags = excluded.flags, "
            " links_json = excluded.links_json;",
            (
                gpo.id,
                gpo.engagement_id,
                gpo.domain_id,
                gpo.guid,
                gpo.dn,
                gpo.display_name,
                gpo.file_sys_path,
                gpo.version_number,
                gpo.flags,
                json.dumps([link.model_dump() for link in gpo.links]),
            ),
        )
        return gpo

    def list_gpos(self, engagement_id: str) -> list[GroupPolicy]:
        rows = self._conn.execute(
            "SELECT * FROM gpos WHERE engagement_id = ? ORDER BY display_name;",
            (engagement_id,),
        ).fetchall()
        return [
            GroupPolicy(
                id=r["id"],
                engagement_id=r["engagement_id"],
                domain_id=r["domain_id"],
                guid=r["guid"],
                dn=r["dn"],
                display_name=r["display_name"],
                file_sys_path=r["file_sys_path"],
                version_number=r["version_number"],
                flags=r["flags"],
                links=[GpoLink.model_validate(x) for x in json.loads(r["links_json"])],
            )
            for r in rows
        ]
