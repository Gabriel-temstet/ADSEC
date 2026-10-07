"""Audit log append-only : trace chaque operation reseau du moteur.

Format JSON Lines, un fichier par engagement. Ce fichier est distinct des
`scan_events` en base (qui servent a l'observabilite/debug) : l'audit log a
une vocation de preuve d'execution pour le pentester et le cabinet.
"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path

_SECRET_PATTERN = re.compile(
    r"(password|token|ticket|hash|secret|private[_ ]?key)\s*[:=]\s*\S+",
    re.IGNORECASE,
)


def redact(text: str) -> str:
    """Masque toute sous-chaine ressemblant a un secret dans un texte libre."""
    return _SECRET_PATTERN.sub(lambda m: m.group(1) + "=[REDACTED]", text)


@dataclass
class AuditEntry:
    timestamp: str
    engagement_id: str
    operator: str
    target: str
    operation: str
    plugin: str | None
    result: str
    extra: dict[str, str] = field(default_factory=dict)


class AuditLog:
    """Ecrit un journal d'audit JSONL append-only pour un engagement donne."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._path.parent.mkdir(parents=True, exist_ok=True)

    @property
    def path(self) -> Path:
        return self._path

    def record(
        self,
        *,
        engagement_id: str,
        operator: str,
        target: str,
        operation: str,
        result: str,
        plugin: str | None = None,
        extra: dict[str, str] | None = None,
    ) -> AuditEntry:
        entry = AuditEntry(
            timestamp=datetime.now(UTC).isoformat(),
            engagement_id=engagement_id,
            operator=redact(operator),
            target=redact(target),
            operation=redact(operation),
            plugin=plugin,
            result=redact(result),
            extra={k: redact(v) for k, v in (extra or {}).items()},
        )
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        return entry

    def read_all(self) -> list[AuditEntry]:
        if not self._path.exists():
            return []
        entries = []
        with self._path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    entries.append(AuditEntry(**json.loads(line)))
        return entries
