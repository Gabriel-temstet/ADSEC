"""Calcul du diff entre une baseline et l'etat courant d'un engagement."""

from __future__ import annotations

from dataclasses import dataclass, field

from adsec.database.repositories.baseline import Baseline
from adsec.database.repositories.findings import StoredFinding


@dataclass
class DiffResult:
    new_findings: list[StoredFinding] = field(default_factory=list)
    resolved_fingerprints: list[str] = field(default_factory=list)
    unchanged_count: int = 0
    object_count_deltas: dict[str, int] = field(default_factory=dict)


def compute_diff(
    baseline: Baseline, current_findings: list[StoredFinding], current_counts: dict[str, int]
) -> DiffResult:
    current_fingerprints = {f.fingerprint: f for f in current_findings}
    new_fps = set(current_fingerprints) - baseline.finding_fingerprints
    resolved_fps = baseline.finding_fingerprints - set(current_fingerprints)
    unchanged = set(current_fingerprints) & baseline.finding_fingerprints

    deltas = {}
    all_keys = set(baseline.object_counts) | set(current_counts)
    for key in all_keys:
        delta = current_counts.get(key, 0) - baseline.object_counts.get(key, 0)
        if delta != 0:
            deltas[key] = delta

    return DiffResult(
        new_findings=[current_fingerprints[fp] for fp in sorted(new_fps)],
        resolved_fingerprints=sorted(resolved_fps),
        unchanged_count=len(unchanged),
        object_count_deltas=deltas,
    )
