"""Repository pour les scan_jobs et scan_events (tracabilite/observabilite)."""

from __future__ import annotations

import json
import sqlite3

from adsec.core.models.enums import LogLevel, ScanJobStatus, ScanProfile
from adsec.core.models.scan import ScanEvent, ScanJob


class ScanJobRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def create(self, job: ScanJob) -> ScanJob:
        self._conn.execute(
            "INSERT INTO scan_jobs "
            "(id, engagement_id, profile, status, tool_version, plugin_versions_json, "
            " configuration_hash, started_at, ended_at, operator) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
            (
                job.id,
                job.engagement_id,
                job.profile.value,
                job.status.value,
                job.tool_version,
                json.dumps(job.plugin_versions),
                job.configuration_hash,
                job.started_at.isoformat() if job.started_at else None,
                job.ended_at.isoformat() if job.ended_at else None,
                job.operator,
            ),
        )
        return job

    def update_status(
        self,
        job_id: str,
        status: ScanJobStatus,
        started_at: str | None = None,
        ended_at: str | None = None,
    ) -> None:
        self._conn.execute(
            "UPDATE scan_jobs SET status = ?, "
            "started_at = COALESCE(?, started_at), "
            "ended_at = COALESCE(?, ended_at) "
            "WHERE id = ?;",
            (status.value, started_at, ended_at, job_id),
        )

    def get_by_id(self, job_id: str) -> ScanJob | None:
        row = self._conn.execute("SELECT * FROM scan_jobs WHERE id = ?;", (job_id,)).fetchone()
        return self._row_to_model(row) if row else None

    def list_for_engagement(self, engagement_id: str) -> list[ScanJob]:
        rows = self._conn.execute(
            "SELECT * FROM scan_jobs WHERE engagement_id = ? ORDER BY rowid DESC;",
            (engagement_id,),
        ).fetchall()
        return [self._row_to_model(r) for r in rows]

    def add_event(self, event: ScanEvent) -> ScanEvent:
        self._conn.execute(
            "INSERT INTO scan_events "
            "(id, scan_job_id, timestamp, level, component, message, data_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?);",
            (
                event.id,
                event.scan_job_id,
                event.timestamp.isoformat(),
                event.level.value,
                event.component,
                event.message,
                json.dumps(event.data),
            ),
        )
        return event

    def list_events(self, scan_job_id: str) -> list[ScanEvent]:
        rows = self._conn.execute(
            "SELECT * FROM scan_events WHERE scan_job_id = ? ORDER BY timestamp;",
            (scan_job_id,),
        ).fetchall()
        return [
            ScanEvent(
                id=r["id"],
                scan_job_id=r["scan_job_id"],
                timestamp=r["timestamp"],
                level=LogLevel(r["level"]),
                component=r["component"],
                message=r["message"],
                data=json.loads(r["data_json"]),
            )
            for r in rows
        ]

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> ScanJob:
        return ScanJob(
            id=row["id"],
            engagement_id=row["engagement_id"],
            profile=ScanProfile(row["profile"]),
            status=ScanJobStatus(row["status"]),
            tool_version=row["tool_version"],
            plugin_versions=json.loads(row["plugin_versions_json"]),
            configuration_hash=row["configuration_hash"],
            started_at=row["started_at"],
            ended_at=row["ended_at"],
            operator=row["operator"],
        )
