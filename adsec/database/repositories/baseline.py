"""Repository des baselines, utilisees par `adsec diff` pour comparer l'etat
courant de l'engagement a un instant precedent."""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4


@dataclass
class Baseline:
    id: str
    engagement_id: str
    label: str
    created_at: str
    finding_fingerprints: set[str]
    object_counts: dict[str, int]


class BaselineRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def create(
        self, engagement_id: str, label: str, fingerprints: set[str], object_counts: dict[str, int]
    ) -> Baseline:
        baseline = Baseline(
            id=f"BASE-{uuid4().hex[:12]}",
            engagement_id=engagement_id,
            label=label,
            created_at=datetime.now(UTC).isoformat(),
            finding_fingerprints=fingerprints,
            object_counts=object_counts,
        )
        self._conn.execute(
            "INSERT INTO baselines "
            "(id, engagement_id, label, created_at, finding_fingerprints_json, object_counts_json) "
            "VALUES (?, ?, ?, ?, ?, ?);",
            (
                baseline.id,
                baseline.engagement_id,
                baseline.label,
                baseline.created_at,
                json.dumps(sorted(fingerprints)),
                json.dumps(object_counts),
            ),
        )
        return baseline

    def get(self, baseline_id: str) -> Baseline | None:
        row = self._conn.execute("SELECT * FROM baselines WHERE id = ?;", (baseline_id,)).fetchone()
        return self._to_model(row) if row else None

    def get_latest(self, engagement_id: str) -> Baseline | None:
        row = self._conn.execute(
            "SELECT * FROM baselines WHERE engagement_id = ? ORDER BY created_at DESC LIMIT 1;",
            (engagement_id,),
        ).fetchone()
        return self._to_model(row) if row else None

    def list(self, engagement_id: str) -> list[Baseline]:
        rows = self._conn.execute(
            "SELECT * FROM baselines WHERE engagement_id = ? ORDER BY created_at DESC;",
            (engagement_id,),
        ).fetchall()
        return [self._to_model(r) for r in rows]

    @staticmethod
    def _to_model(row: sqlite3.Row) -> Baseline:
        return Baseline(
            id=row["id"],
            engagement_id=row["engagement_id"],
            label=row["label"],
            created_at=row["created_at"],
            finding_fingerprints=set(json.loads(row["finding_fingerprints_json"])),
            object_counts=json.loads(row["object_counts_json"]),
        )
