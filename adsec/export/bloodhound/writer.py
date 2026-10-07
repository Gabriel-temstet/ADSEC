"""Ecrit l'export BloodHound-compatible sur disque : un fichier JSON par
type d'objet, plus `relationships.json`, chacun avec une enveloppe `meta`
standard (type, compte, horodatage, version du format)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

from adsec.export.bloodhound.adapter import BloodHoundExport

_FORMAT_VERSION = 5


def _write_collection(path: Path, bh_type: str, data: list[dict[str, object]]) -> None:
    payload = {
        "data": data,
        "meta": {
            "type": bh_type,
            "count": len(data),
            "version": _FORMAT_VERSION,
            "generated_at": datetime.now(UTC).isoformat(),
            "generator": "adsec",
        },
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")


def write_bloodhound_export(export: BloodHoundExport, output_dir: Path) -> list[Path]:
    """Ecrit les 6 fichiers dans `output_dir` (cree si besoin). Retourne
    les chemins ecrits, dans un ordre stable."""
    output_dir.mkdir(parents=True, exist_ok=True)
    files = [
        (output_dir / "users.json", "users", export.users),
        (output_dir / "groups.json", "groups", export.groups),
        (output_dir / "computers.json", "computers", export.computers),
        (output_dir / "domains.json", "domains", export.domains),
        (output_dir / "gpos.json", "gpos", export.gpos),
        (output_dir / "relationships.json", "relationships", export.relationships),
    ]
    for path, bh_type, data in files:
        _write_collection(path, bh_type, data)
    return [path for path, _, _ in files]
