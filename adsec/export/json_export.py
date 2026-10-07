"""Export JSON brut des findings et de leurs preuves. Structure suffisamment
decrite pour etre consommee par une plateforme externe (voir brief
produit, section Formats de sortie)."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from adsec.database.repositories.findings import StoredFinding


def findings_to_dicts(findings: list[StoredFinding]) -> list[dict[str, object]]:
    result = []
    for f in findings:
        row = asdict(f)
        row["severity"] = f.severity.value
        row["confidence"] = f.confidence.value
        row["status"] = f.status.value
        result.append(row)
    return result


def export_findings_json(findings: list[StoredFinding], output_path: Path) -> Path:
    payload = {
        "format": "adsec-findings",
        "version": 1,
        "count": len(findings),
        "findings": findings_to_dicts(findings),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    return output_path
