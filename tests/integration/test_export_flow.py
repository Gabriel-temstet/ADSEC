from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from adsec.cli import context as cli_context
from adsec.cli.commands import scan as scan_cmd
from adsec.cli.main import app
from tests.fixtures.corp_example import DC_HOSTNAME, build_mock_connection
from tests.fixtures.fake_dns import build_fake_dns_probe
from tests.fixtures.fake_smb import build_fake_smb_session

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ADSEC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADSEC_LDAP_BIND_DN", "CN=audit,CN=Users,DC=corp,DC=example")
    monkeypatch.setenv("ADSEC_LDAP_BIND_PASSWORD", "x")
    cli_context.reset_context()
    scan_cmd.set_connection_factory(build_mock_connection)
    scan_cmd.set_smb_session_factory(build_fake_smb_session)
    scan_cmd.set_dns_probe_factory(build_fake_dns_probe)
    yield
    scan_cmd.set_connection_factory(None)
    scan_cmd.set_smb_session_factory(None)
    scan_cmd.set_dns_probe_factory(None)
    cli_context.reset_context()


def test_export_bloodhound_writes_six_files(tmp_path: Path) -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    assert runner.invoke(app, ["scope", "add", "CORP-001", "domain", "corp.example"]).exit_code == 0
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"]).exit_code
        == 0
    )

    out_dir = tmp_path / "bh-out"
    result = runner.invoke(app, ["export", "bloodhound", "CORP-001", "--output", str(out_dir)])
    assert result.exit_code == 0, result.output

    expected = {"users", "groups", "computers", "domains", "gpos", "relationships"}
    actual = {p.stem for p in out_dir.glob("*.json")}
    assert actual == expected

    relationships = json.loads((out_dir / "relationships.json").read_text())
    assert relationships["meta"]["count"] > 0
    users = json.loads((out_dir / "users.json").read_text())
    assert users["meta"]["count"] == 6


def test_export_without_scan_fails() -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    result = runner.invoke(app, ["export", "bloodhound", "CORP-001"])
    assert result.exit_code == 1
