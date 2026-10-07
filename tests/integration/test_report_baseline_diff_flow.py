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


def _setup_and_scan() -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    assert runner.invoke(app, ["scope", "add", "CORP-001", "domain", "corp.example"]).exit_code == 0
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"]).exit_code
        == 0
    )


@pytest.mark.parametrize(
    ("fmt", "kind"),
    [
        ("markdown", "executive"),
        ("markdown", "technical"),
        ("html", "executive"),
        ("html", "technical"),
    ],
)
def test_report_generate_all_narrative_formats(tmp_path: Path, fmt: str, kind: str) -> None:
    _setup_and_scan()
    out = tmp_path / f"report.{fmt[:2]}"
    result = runner.invoke(
        app,
        ["report", "generate", "CORP-001", "--kind", kind, "--format", fmt, "--output", str(out)],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    content = out.read_text()
    assert "CORP" in content


def test_report_json_and_csv(tmp_path: Path) -> None:
    _setup_and_scan()
    json_out = tmp_path / "f.json"
    csv_out = tmp_path / "f.csv"
    assert (
        runner.invoke(
            app, ["report", "generate", "CORP-001", "--format", "json", "--output", str(json_out)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            app, ["report", "generate", "CORP-001", "--format", "csv", "--output", str(csv_out)]
        ).exit_code
        == 0
    )
    payload = json.loads(json_out.read_text())
    assert payload["count"] > 0
    assert "rule_id" in csv_out.read_text()


def test_report_sanitize_masks_evidence(tmp_path: Path) -> None:
    _setup_and_scan()
    out = tmp_path / "sanitized.md"
    result = runner.invoke(
        app,
        [
            "report",
            "generate",
            "CORP-001",
            "--kind",
            "technical",
            "--format",
            "markdown",
            "--sanitize",
            "--output",
            str(out),
        ],
    )
    assert result.exit_code == 0, result.output
    assert out.exists()
    # La logique de masquage elle-meme est testee unitairement (test_reporting.py) ;
    # ce test verifie seulement que --sanitize est bien pris en compte de bout en bout.


def test_baseline_create_then_diff_shows_no_changes() -> None:
    _setup_and_scan()
    create = runner.invoke(app, ["baseline", "create", "CORP-001", "--label", "initial"])
    assert create.exit_code == 0, create.output

    diff_result = runner.invoke(app, ["diff", "CORP-001"])
    assert diff_result.exit_code == 0, diff_result.output
    assert "0 NOUVEAU" in diff_result.output
    assert "0 RESOLU" in diff_result.output


def test_baseline_list_shows_created_baseline() -> None:
    _setup_and_scan()
    runner.invoke(app, ["baseline", "create", "CORP-001", "--label", "v1"])
    result = runner.invoke(app, ["baseline", "list", "CORP-001"])
    assert result.exit_code == 0
    assert "v1" in result.output


def test_diff_without_baseline_fails() -> None:
    _setup_and_scan()
    result = runner.invoke(app, ["diff", "CORP-001"])
    assert result.exit_code == 1


def test_report_without_findings_json_fails() -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    result = runner.invoke(app, ["report", "generate", "CORP-001", "--format", "json"])
    assert result.exit_code == 1
