"""Repository pour les entrees de scope d'un engagement."""

from __future__ import annotations

import sqlite3

from adsec.core.models.engagement import Scope, ScopeEntry
from adsec.core.models.enums import ScopeEntryType


class ScopeRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def add(self, entry: ScopeEntry) -> ScopeEntry:
        self._conn.execute(
            "INSERT OR IGNORE INTO scopes (id, engagement_id, entry_type, value) "
            "VALUES (?, ?, ?, ?);",
            (entry.id, entry.engagement_id, entry.entry_type.value, entry.value),
        )
        return entry

    def remove(self, engagement_id: str, entry_type: ScopeEntryType, value: str) -> bool:
        cur = self._conn.execute(
            "DELETE FROM scopes WHERE engagement_id = ? AND entry_type = ? AND value = ?;",
            (engagement_id, entry_type.value, value),
        )
        return cur.rowcount > 0

    def list_for_engagement(self, engagement_id: str) -> list[ScopeEntry]:
        rows = self._conn.execute(
            "SELECT * FROM scopes WHERE engagement_id = ? ORDER BY entry_type, value;",
            (engagement_id,),
        ).fetchall()
        return [
            ScopeEntry(
                id=r["id"],
                engagement_id=r["engagement_id"],
                entry_type=ScopeEntryType(r["entry_type"]),
                value=r["value"],
            )
            for r in rows
        ]

    def build_scope(self, engagement_id: str, intrusive_actions_enabled: bool = False) -> Scope:
        entries = self.list_for_engagement(engagement_id)
        scope = Scope.from_entries(engagement_id, entries)
        scope.intrusive_actions_enabled = intrusive_actions_enabled
        return scope
