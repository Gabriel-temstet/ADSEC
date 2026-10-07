from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from adsec.cli import context as cli_context
from adsec.cli.commands import scan as scan_cmd
from adsec.cli.main import app
from adsec.core.events.audit_log import AuditLog
from tests.fixtures.corp_example import DC_HOSTNAME, build_mock_connection

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ADSEC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.delenv("ADSEC_LDAP_BIND_DN", raising=False)
    monkeypatch.delenv("ADSEC_LDAP_BIND_PASSWORD", raising=False)
    cli_context.reset_context()
    scan_cmd.set_connection_factory(build_mock_connection)
    yield
    scan_cmd.set_connection_factory(None)
    cli_context.reset_context()


def _setup_engagement() -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    assert runner.invoke(app, ["scope", "add", "CORP-001", "domain", "corp.example"]).exit_code == 0


def test_full_scan_and_inventory() -> None:
    _setup_engagement()
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME])
    assert result.exit_code == 0, result.output
    assert "corp.example" in result.output
    assert "completed" in result.output

    inv = runner.invoke(app, ["scan", "inventory", "CORP-001"])
    assert inv.exit_code == 0, inv.output
    assert "utilisateurs" in inv.output

    ctx = cli_context.get_context()
    from adsec.database.repositories.directory import DirectoryRepository
    from adsec.database.repositories.engagements import EngagementRepository

    eng = EngagementRepository(ctx.database.connection).resolve("CORP-001")
    directory = DirectoryRepository(ctx.database.connection)
    assert len(directory.list_users(eng.id)) == 6
    assert len(directory.list_groups(eng.id)) == 2
    assert len(directory.list_computers(eng.id)) == 4
    assert len(directory.list_ous(eng.id)) == 2
    assert len(directory.list_all_memberships(eng.id)) == 3

    audit = AuditLog(ctx.settings.audit_log_dir / f"{eng.id}.jsonl").read_all()
    operations = [e.operation for e in audit]
    assert "ldap-discovery" in operations
    assert "ldap-collection" in operations


def test_rescan_is_idempotent() -> None:
    _setup_engagement()
    assert runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME]).exit_code == 0
    assert runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME]).exit_code == 0

    ctx = cli_context.get_context()
    from adsec.database.repositories.directory import DirectoryRepository
    from adsec.database.repositories.engagements import EngagementRepository

    eng = EngagementRepository(ctx.database.connection).resolve("CORP-001")
    directory = DirectoryRepository(ctx.database.connection)
    assert len(directory.list_users(eng.id)) == 6
    assert len(directory.list_all_memberships(eng.id)) == 3


def test_passive_profile_skips_collection() -> None:
    _setup_engagement()
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "passive"])
    assert result.exit_code == 0, result.output
    assert "collecte desactivee" in result.output

    inv = runner.invoke(app, ["scan", "inventory", "CORP-001"])
    assert inv.exit_code == 0
    ctx = cli_context.get_context()
    from adsec.database.repositories.directory import DirectoryRepository
    from adsec.database.repositories.engagements import EngagementRepository

    eng = EngagementRepository(ctx.database.connection).resolve("CORP-001")
    assert DirectoryRepository(ctx.database.connection).list_users(eng.id) == []


def test_out_of_scope_target_refused() -> None:
    _setup_engagement()
    result = runner.invoke(app, ["scan", "run", "CORP-001", "dc.evil.com"])
    assert result.exit_code == 1
    assert "hors scope" in result.output


def test_empty_scope_refused() -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME])
    assert result.exit_code == 1
    assert "Scope vide" in result.output


def test_inventory_without_scan_fails() -> None:
    _setup_engagement()
    result = runner.invoke(app, ["scan", "inventory", "CORP-001"])
    assert result.exit_code == 1
