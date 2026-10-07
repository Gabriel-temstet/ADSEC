"""Repository pour l'entite Engagement."""

from __future__ import annotations

import sqlite3

from adsec.core.models.engagement import Engagement
from adsec.core.models.enums import EngagementStatus, ScanProfile


class EngagementAlreadyExistsError(Exception):
    pass


class EngagementNotFoundError(Exception):
    pass


class EngagementRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def create(self, engagement: Engagement) -> Engagement:
        try:
            self._conn.execute(
                "INSERT INTO engagements "
                "(id, client_id, name, status, default_profile, roe_reference, "
                " operator, created_at, started_at, ended_at, config_hash) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    engagement.id,
                    engagement.client_id,
                    engagement.name,
                    engagement.status.value,
                    engagement.default_profile.value,
                    engagement.roe_reference,
                    engagement.operator,
                    engagement.created_at.isoformat(),
                    engagement.started_at.isoformat() if engagement.started_at else None,
                    engagement.ended_at.isoformat() if engagement.ended_at else None,
                    engagement.config_hash,
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise EngagementAlreadyExistsError(
                f"Un engagement nomme {engagement.name!r} existe deja pour ce client"
            ) from exc
        return engagement

    def get_by_id(self, engagement_id: str) -> Engagement | None:
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ?;", (engagement_id,)
        ).fetchone()
        return self._row_to_model(row) if row else None

    def get_by_name(self, client_id: str, name: str) -> Engagement | None:
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE client_id = ? AND name = ?;",
            (client_id, name),
        ).fetchone()
        return self._row_to_model(row) if row else None

    def resolve(self, identifier: str) -> Engagement:
        """Resout un engagement par id ou par nom (pratique pour la CLI)."""
        row = self._conn.execute(
            "SELECT * FROM engagements WHERE id = ? OR name = ?;",
            (identifier, identifier),
        ).fetchone()
        if row is None:
            raise EngagementNotFoundError(f"Engagement introuvable: {identifier!r}")
        return self._row_to_model(row)

    def list_for_client(self, client_id: str) -> list[Engagement]:
        rows = self._conn.execute(
            "SELECT * FROM engagements WHERE client_id = ? ORDER BY created_at;",
            (client_id,),
        ).fetchall()
        return [self._row_to_model(r) for r in rows]

    def update_status(self, engagement_id: str, status: EngagementStatus) -> None:
        cur = self._conn.execute(
            "UPDATE engagements SET status = ? WHERE id = ?;",
            (status.value, engagement_id),
        )
        if cur.rowcount == 0:
            raise EngagementNotFoundError(f"Engagement introuvable: {engagement_id!r}")

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> Engagement:
        return Engagement(
            id=row["id"],
            client_id=row["client_id"],
            name=row["name"],
            status=EngagementStatus(row["status"]),
            default_profile=ScanProfile(row["default_profile"]),
            roe_reference=row["roe_reference"],
            operator=row["operator"],
            created_at=row["created_at"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            config_hash=row["config_hash"],
        )
