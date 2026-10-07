"""Repository pour les observations SMB (hotes/partages) et DNS (zones)."""

from __future__ import annotations

import sqlite3

from adsec.core.models.network import DnsZoneCheck, SmbHost, SmbShare


class SmbRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert_host(self, host: SmbHost) -> SmbHost:
        row = self._conn.execute(
            "SELECT id FROM smb_hosts WHERE engagement_id = ? AND hostname = ?;",
            (host.engagement_id, host.hostname),
        ).fetchone()
        if row is not None:
            host = host.model_copy(update={"id": row["id"]})
            self._conn.execute("DELETE FROM smb_shares WHERE host_id = ?;", (host.id,))

        self._conn.execute(
            "INSERT INTO smb_hosts (id, engagement_id, hostname, dialect, is_smb1, "
            " signing_required, guest_or_anonymous) "
            "VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " dialect = excluded.dialect, is_smb1 = excluded.is_smb1, "
            " signing_required = excluded.signing_required, "
            " guest_or_anonymous = excluded.guest_or_anonymous;",
            (
                host.id,
                host.engagement_id,
                host.hostname,
                host.dialect,
                int(host.is_smb1),
                int(host.signing_required),
                int(host.guest_or_anonymous),
            ),
        )
        for share in host.shares:
            self._conn.execute(
                "INSERT INTO smb_shares "
                "(id, engagement_id, host_id, name, remark, is_hidden_admin_share, anonymous_readable) "
                "VALUES (?, ?, ?, ?, ?, ?, ?);",
                (
                    f"SHR-{host.id}-{share.name}",
                    host.engagement_id,
                    host.id,
                    share.name,
                    share.remark,
                    int(share.is_hidden_admin_share),
                    int(share.anonymous_readable),
                ),
            )
        return host

    def list_hosts(self, engagement_id: str) -> list[SmbHost]:
        rows = self._conn.execute(
            "SELECT * FROM smb_hosts WHERE engagement_id = ? ORDER BY hostname;",
            (engagement_id,),
        ).fetchall()
        hosts = []
        for row in rows:
            share_rows = self._conn.execute(
                "SELECT * FROM smb_shares WHERE host_id = ? ORDER BY name;", (row["id"],)
            ).fetchall()
            hosts.append(
                SmbHost(
                    id=row["id"],
                    engagement_id=row["engagement_id"],
                    hostname=row["hostname"],
                    dialect=row["dialect"],
                    is_smb1=bool(row["is_smb1"]),
                    signing_required=bool(row["signing_required"]),
                    guest_or_anonymous=bool(row["guest_or_anonymous"]),
                    shares=[
                        SmbShare(
                            name=s["name"],
                            remark=s["remark"] or "",
                            is_hidden_admin_share=bool(s["is_hidden_admin_share"]),
                            anonymous_readable=bool(s["anonymous_readable"]),
                        )
                        for s in share_rows
                    ],
                )
            )
        return hosts


class DnsRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert_zone_check(self, check: DnsZoneCheck) -> DnsZoneCheck:
        row = self._conn.execute(
            "SELECT id FROM dns_zone_checks WHERE engagement_id = ? AND zone = ?;",
            (check.engagement_id, check.zone),
        ).fetchone()
        if row is not None:
            check = check.model_copy(update={"id": row["id"]})
        self._conn.execute(
            "INSERT INTO dns_zone_checks "
            "(id, engagement_id, zone, zone_transfer_allowed, zone_transfer_record_count, "
            " recursion_available) "
            "VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(id) DO UPDATE SET "
            " zone_transfer_allowed = excluded.zone_transfer_allowed, "
            " zone_transfer_record_count = excluded.zone_transfer_record_count, "
            " recursion_available = excluded.recursion_available;",
            (
                check.id,
                check.engagement_id,
                check.zone,
                int(check.zone_transfer_allowed),
                check.zone_transfer_record_count,
                int(check.recursion_available),
            ),
        )
        return check

    def list_zone_checks(self, engagement_id: str) -> list[DnsZoneCheck]:
        rows = self._conn.execute(
            "SELECT * FROM dns_zone_checks WHERE engagement_id = ? ORDER BY zone;",
            (engagement_id,),
        ).fetchall()
        return [
            DnsZoneCheck(
                id=r["id"],
                engagement_id=r["engagement_id"],
                zone=r["zone"],
                zone_transfer_allowed=bool(r["zone_transfer_allowed"]),
                zone_transfer_record_count=r["zone_transfer_record_count"],
                recursion_available=bool(r["recursion_available"]),
            )
            for r in rows
        ]
