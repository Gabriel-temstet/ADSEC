"""Repository pour l'entite Client."""

from __future__ import annotations

import json
import sqlite3

from adsec.core.models.engagement import Client


class ClientAlreadyExistsError(Exception):
    pass


class ClientRepository:
    def __init__(self, conn: sqlite3.Connection) -> None:
        self._conn = conn

    def create(self, client: Client) -> Client:
        try:
            self._conn.execute(
                "INSERT INTO clients (id, name, created_at, metadata_json) VALUES (?, ?, ?, ?);",
                (
                    client.id,
                    client.name,
                    client.created_at.isoformat(),
                    json.dumps(client.metadata),
                ),
            )
        except sqlite3.IntegrityError as exc:
            raise ClientAlreadyExistsError(f"Un client nomme {client.name!r} existe deja") from exc
        return client

    def get_by_id(self, client_id: str) -> Client | None:
        row = self._conn.execute("SELECT * FROM clients WHERE id = ?;", (client_id,)).fetchone()
        return self._row_to_model(row) if row else None

    def get_by_name(self, name: str) -> Client | None:
        row = self._conn.execute("SELECT * FROM clients WHERE name = ?;", (name,)).fetchone()
        return self._row_to_model(row) if row else None

    def list_all(self) -> list[Client]:
        rows = self._conn.execute("SELECT * FROM clients ORDER BY created_at;").fetchall()
        return [self._row_to_model(r) for r in rows]

    @staticmethod
    def _row_to_model(row: sqlite3.Row) -> Client:
        return Client(
            id=row["id"],
            name=row["name"],
            created_at=row["created_at"],
            metadata=json.loads(row["metadata_json"]),
        )
