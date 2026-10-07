"""Connexion SQLite et application des migrations versionnees.

Chaque fichier `NNNN_description.sql` dans `database/schema/` est applique
une seule fois, dans l'ordre numerique, et enregistre dans `schema_version`.
"""

from __future__ import annotations

import re
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Self

_SCHEMA_DIR = Path(__file__).parent / "schema"
_MIGRATION_RE = re.compile(r"^(\d{4})_.*\.sql$")


def _discover_migrations() -> list[tuple[int, Path]]:
    migrations: list[tuple[int, Path]] = []
    for path in _SCHEMA_DIR.glob("*.sql"):
        match = _MIGRATION_RE.match(path.name)
        if match:
            migrations.append((int(match.group(1)), path))
    return sorted(migrations, key=lambda item: item[0])


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Ouvre une connexion SQLite avec les pragmas de securite/robustesse
    adaptes (cles etrangeres actives, mode WAL pour la concurrence lecture)."""
    db_path = Path(db_path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def current_schema_version(conn: sqlite3.Connection) -> int:
    cur = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';"
    )
    if cur.fetchone() is None:
        return 0
    row = conn.execute("SELECT MAX(version) AS v FROM schema_version;").fetchone()
    return int(row["v"]) if row["v"] is not None else 0


def apply_migrations(conn: sqlite3.Connection) -> list[int]:
    """Applique toutes les migrations non encore appliquees. Retourne la
    liste des numeros de version appliques lors de cet appel."""
    current = current_schema_version(conn)
    applied: list[int] = []
    for version, path in _discover_migrations():
        if version <= current:
            continue
        sql = path.read_text(encoding="utf-8")
        # `executescript` commite implicitement toute transaction en cours et
        # s'execute hors du controle transactionnel manuel : chaque
        # instruction du script est donc appliquee immediatement (mode
        # autocommit, isolation_level=None). Les scripts de migration ne
        # doivent contenir que des instructions idempotentes (IF NOT EXISTS).
        conn.executescript(sql)
        conn.execute(
            "INSERT INTO schema_version (version, applied_at) VALUES (?, ?);",
            (version, datetime.now(UTC).isoformat()),
        )
        applied.append(version)
    return applied


class Database:
    """Point d'entree unique vers la base SQLite d'un engagement/du produit.

    Utilisation typique : une base par engagement (isolation physique), ou
    une base unique multi-engagements avec isolation logique par
    `engagement_id` selon le mode de deploiement choisi par l'operateur.
    """

    def __init__(self, db_path: str | Path) -> None:
        self._db_path = Path(db_path)
        self._conn = connect(self._db_path)
        apply_migrations(self._conn)

    @property
    def connection(self) -> sqlite3.Connection:
        return self._conn

    @property
    def path(self) -> Path:
        return self._db_path

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
