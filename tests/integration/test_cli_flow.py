from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from adsec.cli import context as cli_context
from adsec.cli.main import app

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADSEC_DATA_DIR", str(tmp_path / "adsec_data"))
    cli_context.reset_context()
    yield
    cli_context.reset_context()


def test_full_client_engagement_scope_flow() -> None:
    result = runner.invoke(app, ["client", "create", "ACME"])
    assert result.exit_code == 0, result.output

    result = runner.invoke(app, ["engagement", "create", "ACME", "ACME-2026-001"])
    assert result.exit_code == 0, result.output

    result = runner.invoke(app, ["scope", "add", "ACME-2026-001", "domain", "acme.local"])
    assert result.exit_code == 0, result.output

    result = runner.invoke(
        app, ["scope", "add", "ACME-2026-001", "host-exclude", "prod.acme.local"]
    )
    assert result.exit_code == 0, result.output

    result = runner.invoke(app, ["scope", "test", "ACME-2026-001", "dc01.acme.local"])
    assert result.exit_code == 0
    assert "EN SCOPE" in result.output

    result = runner.invoke(app, ["scope", "test", "ACME-2026-001", "prod.acme.local"])
    assert result.exit_code == 0
    assert "HORS SCOPE" in result.output


def test_engagement_create_fails_for_unknown_client() -> None:
    result = runner.invoke(app, ["engagement", "create", "GHOST", "ENG-1"])
    assert result.exit_code == 1
    assert "introuvable" in result.output


def test_doctor_command_succeeds() -> None:
    result = runner.invoke(app, ["doctor", "run"])
    assert result.exit_code == 0
    assert "adsec doctor" in result.output


def test_duplicate_client_creation_fails() -> None:
    result = runner.invoke(app, ["client", "create", "ACME"])
    assert result.exit_code == 0
    result = runner.invoke(app, ["client", "create", "ACME"])
    assert result.exit_code == 1
