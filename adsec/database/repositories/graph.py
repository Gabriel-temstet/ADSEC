"""Repository de persistance des chemins d'attaque calcules."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from uuid import uuid4

from adsec.graph.models import AttackPath, GraphEdge


class AttackPathRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def replace_all(
        self, engagement_id: str, scan_job_id: str | None, paths: list[AttackPath]
    ) -> list[str]:
        """Remplace l'ensemble des chemins d'un engagement par un nouveau
        calcul complet (les chemins sont deterministes a partir des donnees
        courantes, il n'y a pas de notion d'historique a preserver ici,
        contrairement aux findings). Retourne les ids attribues, dans le
        meme ordre que `paths`, pour permettre la correlation avec les
        findings du meme scan."""
        self._conn.execute("DELETE FROM attack_paths WHERE engagement_id = ?;", (engagement_id,))
        now = datetime.now(UTC).isoformat()
        ids: list[str] = []
        for path in paths:
            path_id = f"PATH-{uuid4().hex[:12]}"
            ids.append(path_id)
            self._conn.execute(
                "INSERT INTO attack_paths "
                "(id, engagement_id, scan_job_id, source_id, target_id, length, confidence, "
                " impact_summary, node_ids_json, edges_json, computed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    path_id,
                    engagement_id,
                    scan_job_id,
                    path.source_id,
                    path.target_id,
                    path.length,
                    path.confidence.value,
                    path.impact_summary,
                    json.dumps(path.node_ids),
                    json.dumps([e.model_dump() for e in path.edges]),
                    now,
                ),
            )
        return ids

    def link_findings(self, engagement_id: str, links: list[tuple[str, str]]) -> None:
        """Enregistre des liens (finding_id, attack_path_id). Les liens
        precedents disparaissent avec les anciens chemins qu'ils
        referencaient (ON DELETE CASCADE sur attack_path_id)."""
        for finding_id, path_id in links:
            self._conn.execute(
                "INSERT OR IGNORE INTO finding_attack_paths "
                "(finding_id, attack_path_id, engagement_id) VALUES (?, ?, ?);",
                (finding_id, path_id, engagement_id),
            )

    def list_paths_for_finding(self, finding_id: str) -> list[AttackPath]:
        rows = self._conn.execute(
            "SELECT ap.* FROM attack_paths ap "
            "JOIN finding_attack_paths fap ON fap.attack_path_id = ap.id "
            "WHERE fap.finding_id = ? ORDER BY ap.length;",
            (finding_id,),
        ).fetchall()
        return [self._to_model(r) for r in rows]

    def list_for_target(self, engagement_id: str, target_id: str) -> list[AttackPath]:
        rows = self._conn.execute(
            "SELECT * FROM attack_paths WHERE engagement_id = ? AND target_id = ? "
            "ORDER BY length, source_id;",
            (engagement_id, target_id),
        ).fetchall()
        return [self._to_model(r) for r in rows]

    def list_all(self, engagement_id: str) -> list[AttackPath]:
        rows = self._conn.execute(
            "SELECT * FROM attack_paths WHERE engagement_id = ? ORDER BY target_id, length;",
            (engagement_id,),
        ).fetchall()
        return [self._to_model(r) for r in rows]

    def list_targets(self, engagement_id: str) -> list[str]:
        rows = self._conn.execute(
            "SELECT DISTINCT target_id FROM attack_paths WHERE engagement_id = ? ORDER BY target_id;",
            (engagement_id,),
        ).fetchall()
        return [str(r["target_id"]) for r in rows]

    @staticmethod
    def _to_model(row: sqlite3.Row) -> AttackPath:
        from adsec.core.models.enums import RelationConfidence

        return AttackPath(
            engagement_id=row["engagement_id"],
            source_id=row["source_id"],
            target_id=row["target_id"],
            node_ids=json.loads(row["node_ids_json"]),
            edges=[GraphEdge.model_validate(e) for e in json.loads(row["edges_json"])],
            length=row["length"],
            confidence=RelationConfidence(row["confidence"]),
            impact_summary=row["impact_summary"],
        )
