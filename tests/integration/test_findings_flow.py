from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from adsec.cli import context as cli_context
from adsec.cli.commands import scan as scan_cmd
from adsec.cli.main import app
from adsec.core.models.enums import FindingStatus
from adsec.database.repositories.engagements import EngagementRepository
from adsec.database.repositories.findings import FindingRepository
from tests.fixtures.corp_example import DC_HOSTNAME, build_mock_connection
from tests.fixtures.fake_dns import build_fake_dns_probe
from tests.fixtures.fake_smb import build_fake_smb_session

runner = CliRunner()


@pytest.fixture(autouse=True)
def isolated(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):  # type: ignore[no-untyped-def]
    monkeypatch.setenv("ADSEC_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("ADSEC_LDAP_BIND_DN", "CN=audit,CN=Users,DC=corp,DC=example")
    monkeypatch.setenv("ADSEC_LDAP_BIND_PASSWORD", "test-only-password")
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


def _repo() -> tuple[FindingRepository, str]:
    ctx = cli_context.get_context()
    eng = EngagementRepository(ctx.database.connection).resolve("CORP-001")
    return FindingRepository(ctx.database.connection), eng.id


def test_scan_persists_findings_with_evidence() -> None:
    _setup()
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"])
    assert result.exit_code == 0, result.output

    repo, eng_id = _repo()
    findings = repo.list(eng_id)
    rule_ids = {f.rule_id for f in findings}
    assert rule_ids == {
        "AD-ACL-001",
        "AD-ACL-002",
        "AD-ACL-003",
        "AD-ACL-004",
        "AD-ACL-005",
        "AD-GPO-001",
        "AD-GPO-002",
        "AD-KRB-001",
        "AD-KRB-002",
        "AD-KRB-003",
        "AD-KRB-004",
        "AD-KRB-005",
        "AD-KRB-006",
        "AD-TRUST-001",
        "AD-SMB-001",
        "AD-SMB-002",
        "AD-SMB-003",
        "AD-SMB-004",
        "AD-DNS-001",
        "AD-DNS-002",
    }
    assert findings[0].severity.value == "critical"  # tri par severite
    assert all(f.evidence for f in findings)
    assert all(len(f.evidence[0].hash) == 64 for f in findings)


def test_safe_profile_excludes_trust_checks() -> None:
    _setup()
    assert (
        runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "safe"]).exit_code
        == 0
    )
    repo, eng_id = _repo()
    assert "AD-TRUST-001" not in {f.rule_id for f in repo.list(eng_id)}
    assert "AD-ACL-001" in {f.rule_id for f in repo.list(eng_id)}


def test_rescan_deduplicates_and_preserves_status() -> None:
    _setup()
    assert (
        runner.invoke(
            app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"]
        ).exit_code
        == 0
    )
    repo, eng_id = _repo()
    first = repo.list(eng_id)
    target = first[0]
    assert (
        runner.invoke(
            app, ["findings", "status", "CORP-001", target.id, "false_positive"]
        ).exit_code
        == 0
    )

    assert (
        runner.invoke(
            app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"]
        ).exit_code
        == 0
    )
    second = repo.list(eng_id)
    assert len(second) == len(first)  # pas de doublon
    same = repo.get(target.id)
    assert same is not None
    assert same.status == FindingStatus.FALSE_POSITIVE  # statut du pentester preserve
    assert same.first_seen == target.first_seen
    assert same.last_seen >= target.last_seen


def test_findings_cli_list_and_show() -> None:
    _setup()
    assert (
        runner.invoke(
            app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"]
        ).exit_code
        == 0
    )
    listing = runner.invoke(app, ["findings", "list", "CORP-001", "--rule", "AD-ACL-001"])
    assert listing.exit_code == 0, listing.output
    assert "AD-ACL-001" in listing.output

    repo, eng_id = _repo()
    finding = repo.list(eng_id, rule_id="AD-ACL-001")[0]
    shown = runner.invoke(app, ["findings", "show", "CORP-001", finding.id])
    assert shown.exit_code == 0, shown.output
    assert "Procedure de validation" in shown.output
    assert "aucun mapping fiable" in shown.output

    missing = runner.invoke(app, ["findings", "show", "CORP-001", "FND-doesnotexist"])
    assert missing.exit_code == 1


def test_anonymous_scan_reports_skipped_checks(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("ADSEC_LDAP_BIND_DN")
    monkeypatch.delenv("ADSEC_LDAP_BIND_PASSWORD")
    _setup()
    result = runner.invoke(app, ["scan", "run", "CORP-001", DC_HOSTNAME, "--profile", "standard"])
    assert result.exit_code == 0, result.output
    assert "ignore(s) faute de niveau" in result.output
    repo, eng_id = _repo()
    rule_ids = {f.rule_id for f in repo.list(eng_id)}
    # LDAP anonyme : ACL/Kerberos/GPO/Trust necessitent une authentification et sont ignores.
    assert not rule_ids & {"AD-ACL-001", "AD-KRB-001", "AD-GPO-001", "AD-TRUST-001"}
    # SMB/DNS restent testables sans identifiants LDAP (protocoles independants).
    assert rule_ids & {"AD-SMB-001", "AD-DNS-001"}
