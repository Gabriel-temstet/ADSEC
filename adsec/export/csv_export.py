"""Export CSV des findings : une ligne par finding (les preuves multiples
sont jointes dans une seule cellule, le CSV n'etant pas structure)."""

from __future__ import annotations

import csv
import io
from pathlib import Path

from adsec.database.repositories.findings import StoredFinding

_COLUMNS = [
    "id",
    "rule_id",
    "title",
    "category",
    "severity",
    "confidence",
    "status",
    "affected_assets",
    "first_seen",
    "last_seen",
    "evidence_count",
]


def findings_to_csv_text(findings: list[StoredFinding]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(_COLUMNS)
    for f in findings:
        writer.writerow(
            [
                f.id,
                f.rule_id,
                f.title,
                f.category,
                f.severity.value,
                f.confidence.value,
                f.status.value,
                "; ".join(f.affected_assets),
                f.first_seen,
                f.last_seen,
                str(len(f.evidence)),
            ]
        )
    return buffer.getvalue()


def export_findings_csv(findings: list[StoredFinding], output_path: Path) -> Path:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(findings_to_csv_text(findings), encoding="utf-8", newline="")
    return output_path
