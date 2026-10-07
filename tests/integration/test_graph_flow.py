from __future__ import annotations

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


def _setup() -> None:
    assert runner.invoke(app, ["client", "create", "CORP"]).exit_code == 0
    assert runner.invoke(app, ["engagement", "create", "CORP", "CORP-001"]).exit_code == 0
    assert runner.invoke(app, ["scope", "add", "CORP-001", "domain", "corp.example"]).exit_code == 0


def test_deep_profile_computes_and_persists_attack_paths() -> None:
    _setup()
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"])
    assert result.exit_code == 0, result.output
    assert "attack_paths" in result.output

    targets = runner.invoke(app, ["graph", "targets", "CORP-001"])
    assert targets.exit_code == 0
    assert "Domain Admins" in targets.output
    assert "corp.example" in targets.output

    show = runner.invoke(
        app, ["graph", "show", "CORP-001", "CN=Domain Admins,CN=Users,DC=corp,DC=example"]
    )
    assert show.exit_code == 0, show.output
    assert "Alice" in show.output

    # Chemin multi-sauts via ForceChangePassword puis appartenance au groupe.
    assert "Svc" in show.output and "Sql" in show.output


def test_standard_profile_does_not_compute_attack_paths() -> None:
    _setup()
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"])
    assert result.exit_code == 0, result.output
    assert "attack_paths" not in result.output

    targets = runner.invoke(app, ["graph", "targets", "CORP-001"])
    assert targets.exit_code == 0
    assert "Aucun chemin d'attaque calcule" in targets.output


def test_rescan_replaces_previous_paths_without_duplication() -> None:
    _setup()
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"]).exit_code
        == 0
    )
    first = runner.invoke(app, ["graph", "show", "CORP-001", "corp.example"]).output
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"]).exit_code
        == 0
    )
    second = runner.invoke(app, ["graph", "show", "CORP-001", "corp.example"]).output
    assert first == second  # deterministe, pas de doublon apres un second scan


def test_graph_show_unknown_target_fails() -> None:
    _setup()
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"]).exit_code
        == 0
    )
    result = runner.invoke(app, ["graph", "show", "CORP-001", "CN=DoesNotExist"])
    assert result.exit_code == 1


def test_deep_scan_correlates_findings_with_paths_and_shows_risk() -> None:
    _setup()
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "deep"]).exit_code
        == 0
    )

    from adsec.database.repositories.engagements import EngagementRepository
    from adsec.database.repositories.findings import FindingRepository

    ctx = cli_context.get_context()
    eng = EngagementRepository(ctx.database.connection).resolve("CORP-001")
    dcsync_finding = FindingRepository(ctx.database.connection).list(eng.id, rule_id="AD-ACL-005")[
        0
    ]

    result = runner.invoke(app, ["findings", "show", "CORP-001", dcsync_finding.id])
    assert result.exit_code == 0, result.output
    assert "Modele de risque" in result.output
    assert "domain_wide" in result.output
    assert "Chemins d'attaque correles" in result.output


def test_standard_scan_findings_show_has_no_correlated_paths() -> None:
    _setup()
    assert (
        runner.invoke(
            app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"]
        ).exit_code
        == 0
    )

    from adsec.database.repositories.engagements import EngagementRepository
    from adsec.database.repositories.findings import FindingRepository

    ctx = cli_context.get_context()
    eng = EngagementRepository(ctx.database.connection).resolve("CORP-001")
    finding = FindingRepository(ctx.database.connection).list(eng.id, rule_id="AD-ACL-005")[0]

    result = runner.invoke(app, ["findings", "show", "CORP-001", finding.id])
    assert result.exit_code == 0, result.output
    assert "Aucun chemin d'attaque correle" in result.output
    assert "Chemins d'attaque correles" not in result.output
