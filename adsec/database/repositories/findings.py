"""Repository des findings et de leurs preuves.

Deduplication : un finding est identifie par (engagement_id, fingerprint).
Un re-scan qui redecouvre le meme probleme met a jour `last_seen`, le
contenu descriptif et les preuves, mais PRESERVE le statut choisi par le
pentester (CONFIRMED, FALSE_POSITIVE, ACCEPTED_RISK, REMEDIATED) et
`first_seen`."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from uuid import uuid4

from adsec.core.models.enums import Confidence, FindingStatus, Severity
from adsec.rules.base import EvidenceRef, Finding


@dataclass
class StoredEvidence:
    id: str
    source: str
    timestamp: str
    object_type: str
    object_id: str
    attribute: str
    value: str
    hash: str
    collector_version: str


@dataclass
class StoredFinding:
    id: str
    engagement_id: str
    scan_job_id: str | None
    rule_id: str
    fingerprint: str
    title: str
    category: str
    severity: Severity
    confidence: Confidence
    status: FindingStatus
    affected_assets: list[str]
    description: str
    technical_details: str
    impact: str
    validation_procedure: str
    remediation: str
    references: list[str]
    mitre_technique_id: str | None
    first_seen: str
    last_seen: str
    evidence: list[StoredEvidence]


def evidence_hash(ev: EvidenceRef) -> str:
    raw = f"{ev.source}|{ev.object_type}|{ev.object_id}|{ev.attribute}|{ev.value}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FindingRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def upsert(
        self,
        engagement_id: str,
        scan_job_id: str,
        finding: Finding,
        collector_version: str,
    ) -> tuple[StoredFinding, bool]:
        """Insere ou met a jour un finding. Retourne (finding, cree)."""
        fingerprint = finding.fingerprint()
        now = datetime.now(UTC).isoformat()
        row = self._conn.execute(
            "SELECT id FROM findings WHERE engagement_id = ? AND fingerprint = ?;",
            (engagement_id, fingerprint),
        ).fetchone()
        created = row is None
        finding_id = f"FND-{uuid4().hex[:12]}" if row is None else str(row["id"])

        common = (
            scan_job_id,
            finding.title,
            finding.category,
            finding.severity.value,
            finding.confidence.value,
            json.dumps(finding.affected_assets),
            finding.description,
            finding.technical_details,
            finding.impact,
            finding.validation_procedure,
            finding.remediation,
            json.dumps(finding.references),
            finding.mitre_technique_id,
        )
        if created:
            self._conn.execute(
                "INSERT INTO findings (id, engagement_id, scan_job_id, title, category, "
                " severity, confidence, affected_assets_json, description, technical_details, "
                " impact, validation_procedure, remediation, references_json, "
                " mitre_technique_id, rule_id, fingerprint, status, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    finding_id,
                    engagement_id,
                    *common,
                    finding.rule_id,
                    fingerprint,
                    finding.status.value,
                    finding.first_seen.isoformat(),
                    now,
                ),
            )
        else:
            self._conn.execute(
                "UPDATE findings SET scan_job_id = ?, title = ?, category = ?, severity = ?, "
                " confidence = ?, affected_assets_json = ?, description = ?, "
                " technical_details = ?, impact = ?, validation_procedure = ?, "
                " remediation = ?, references_json = ?, mitre_technique_id = ?, "
                " last_seen = ? WHERE id = ?;",
                (*common, now, finding_id),
            )
            self._conn.execute("DELETE FROM evidence WHERE finding_id = ?;", (finding_id,))

        for ev in finding.evidence:
            self._conn.execute(
                "INSERT INTO evidence (id, engagement_id, finding_id, source, timestamp, "
                " object_type, object_id, attribute, value, hash, collector_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);",
                (
                    f"EV-{uuid4().hex[:12]}",
                    engagement_id,
                    finding_id,
                    ev.source,
                    now,
                    ev.object_type,
                    ev.object_id,
                    ev.attribute,
                    ev.value,
                    evidence_hash(ev),
                    collector_version,
                ),
            )
        stored = self.get(finding_id)
        if stored is None:
            raise RuntimeError(f"Finding {finding_id} introuvable apres ecriture")
        return stored, created

    def get(self, finding_id: str) -> StoredFinding | None:
        row = self._conn.execute("SELECT * FROM findings WHERE id = ?;", (finding_id,)).fetchone()
        return self._to_model(row) if row else None

    def find(self, engagement_id: str, identifier: str) -> StoredFinding | None:
        """Retrouve un finding par id complet, ou prefixe unique d'id / de fingerprint."""
        rows = self._conn.execute(
            "SELECT * FROM findings WHERE engagement_id = ? AND "
            "(id = ? OR id LIKE ? OR fingerprint LIKE ?);",
            (engagement_id, identifier, f"{identifier}%", f"{identifier}%"),
        ).fetchall()
        if len(rows) != 1:
            return None
        return self._to_model(rows[0])

    def list(
        self,
        engagement_id: str,
        rule_id: str | None = None,
        severity: Severity | None = None,
    ) -> list[StoredFinding]:
        query = "SELECT * FROM findings WHERE engagement_id = ?"
        params: list[object] = [engagement_id]
        if rule_id:
            query += " AND rule_id = ?"
            params.append(rule_id)
        if severity:
            query += " AND severity = ?"
            params.append(severity.value)
        rows = self._conn.execute(query + " ORDER BY rule_id, title;", params).fetchall()
        return sorted(
            (self._to_model(r) for r in rows),
            key=lambda f: (_SEVERITY_ORDER[f.severity], f.rule_id, f.title),
        )

    def set_status(self, engagement_id: str, finding_id: str, status: FindingStatus) -> bool:
        cur = self._conn.execute(
            "UPDATE findings SET status = ? WHERE engagement_id = ? AND id = ?;",
            (status.value, engagement_id, finding_id),
        )
        return cur.rowcount > 0

    def _to_model(self, row: sqlite3.Row) -> StoredFinding:
        ev_rows = self._conn.execute(
            "SELECT * FROM evidence WHERE finding_id = ? ORDER BY timestamp;", (row["id"],)
        ).fetchall()
        return StoredFinding(
            id=row["id"],
            engagement_id=row["engagement_id"],
            scan_job_id=row["scan_job_id"],
            rule_id=row["rule_id"],
            fingerprint=row["fingerprint"],
            title=row["title"],
            category=row["category"],
            severity=Severity(row["severity"]),
            confidence=Confidence(row["confidence"]),
            status=FindingStatus(row["status"]),
            affected_assets=json.loads(row["affected_assets_json"]),
            description=row["description"],
            technical_details=row["technical_details"],
            impact=row["impact"],
            validation_procedure=row["validation_procedure"],
            remediation=row["remediation"],
            references=json.loads(row["references_json"]),
            mitre_technique_id=row["mitre_technique_id"],
            first_seen=row["first_seen"],
            last_seen=row["last_seen"],
            evidence=[
                StoredEvidence(
                    id=e["id"],
                    source=e["source"],
                    timestamp=e["timestamp"],
                    object_type=e["object_type"],
                    object_id=e["object_id"],
                    attribute=e["attribute"],
                    value=e["value"],
                    hash=e["hash"],
                    collector_version=e["collector_version"],
                )
                for e in ev_rows
            ],
        )


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}
