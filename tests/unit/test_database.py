from __future__ import annotations

from pathlib import Path

import pytest

from adsec.core.models.engagement import Client, Engagement, ScopeEntry
from adsec.core.models.enums import ScopeEntryType
from adsec.database.connection import Database, apply_migrations, connect, current_schema_version
from adsec.database.repositories.clients import ClientAlreadyExistsError, ClientRepository
from adsec.database.repositories.engagements import (
    EngagementNotFoundError,
    EngagementRepository,
)
from adsec.database.repositories.scopes import ScopeRepository


@pytest.fixture()
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "test.sqlite3")
    yield database
    database.close()


def test_migrations_are_applied_and_idempotent(tmp_path: Path) -> None:
    conn = connect(tmp_path / "migtest.sqlite3")
    applied_first = apply_migrations(conn)
    assert applied_first == [1, 2, 3, 4, 5, 6, 7, 8, 9]
    assert current_schema_version(conn) == 9

    applied_second = apply_migrations(conn)
    assert applied_second == []  # rien a rejouer


def test_client_repository_create_and_get(db: Database) -> None:
    repo = ClientRepository(db.connection)
    client = repo.create(Client(name="ACME"))

    fetched = repo.get_by_id(client.id)
    assert fetched is not None
    assert fetched.name == "ACME"

    by_name = repo.get_by_name("ACME")
    assert by_name is not None
    assert by_name.id == client.id


def test_client_repository_rejects_duplicate_name(db: Database) -> None:
    repo = ClientRepository(db.connection)
    repo.create(Client(name="ACME"))
    with pytest.raises(ClientAlreadyExistsError):
        repo.create(Client(name="ACME"))


def test_engagement_isolation_between_clients(db: Database) -> None:
    client_repo = ClientRepository(db.connection)
    engagement_repo = EngagementRepository(db.connection)

    acme = client_repo.create(Client(name="ACME"))
    other = client_repo.create(Client(name="OTHER"))

    engagement_repo.create(Engagement(client_id=acme.id, name="ENG-1"))
    engagement_repo.create(
        Engagement(client_id=other.id, name="ENG-1")
    )  # meme nom, client different

    acme_engagements = engagement_repo.list_for_client(acme.id)
    other_engagements = engagement_repo.list_for_client(other.id)

    assert len(acme_engagements) == 1
    assert len(other_engagements) == 1
    assert acme_engagements[0].client_id != other_engagements[0].client_id


def test_engagement_resolve_not_found_raises(db: Database) -> None:
    engagement_repo = EngagementRepository(db.connection)
    with pytest.raises(EngagementNotFoundError):
        engagement_repo.resolve("ENG-does-not-exist")


def test_scope_entries_isolated_per_engagement(db: Database) -> None:
    client_repo = ClientRepository(db.connection)
    engagement_repo = EngagementRepository(db.connection)
    scope_repo = ScopeRepository(db.connection)

    client = client_repo.create(Client(name="ACME"))
    eng1 = engagement_repo.create(Engagement(client_id=client.id, name="ENG-1"))
    eng2 = engagement_repo.create(Engagement(client_id=client.id, name="ENG-2"))

    scope_repo.add(
        ScopeEntry(engagement_id=eng1.id, entry_type=ScopeEntryType.DOMAIN, value="acme.local")
    )
    scope_repo.add(
        ScopeEntry(engagement_id=eng2.id, entry_type=ScopeEntryType.DOMAIN, value="other.local")
    )

    entries_1 = scope_repo.list_for_engagement(eng1.id)
    entries_2 = scope_repo.list_for_engagement(eng2.id)

    assert [e.value for e in entries_1] == ["acme.local"]
    assert [e.value for e in entries_2] == ["other.local"]


def test_scope_repository_ignores_exact_duplicate(db: Database) -> None:
    client_repo = ClientRepository(db.connection)
    engagement_repo = EngagementRepository(db.connection)
    scope_repo = ScopeRepository(db.connection)

    client = client_repo.create(Client(name="ACME"))
    eng = engagement_repo.create(Engagement(client_id=client.id, name="ENG-1"))

    scope_repo.add(
        ScopeEntry(engagement_id=eng.id, entry_type=ScopeEntryType.DOMAIN, value="acme.local")
    )
    scope_repo.add(
        ScopeEntry(engagement_id=eng.id, entry_type=ScopeEntryType.DOMAIN, value="acme.local")
    )

    entries = scope_repo.list_for_engagement(eng.id)
    assert len(entries) == 1
