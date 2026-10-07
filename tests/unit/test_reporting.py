from __future__ import annotations

from adsec.core.models.engagement import Engagement
from adsec.core.models.enums import Confidence, FindingStatus, Severity
from adsec.database.repositories.baseline import Baseline
from adsec.database.repositories.findings import StoredEvidence, StoredFinding
from adsec.export.csv_export import findings_to_csv_text
from adsec.export.json_export import findings_to_dicts
from adsec.reporting.data import build_report_data
from adsec.reporting.diff import compute_diff
from adsec.reporting.html import render_executive_html, render_technical_html
from adsec.reporting.markdown import render_executive_markdown, render_technical_markdown
from adsec.reporting.sanitizer import sanitize_text


def _finding(rule_id="AD-ACL-001", severity=Severity.HIGH, title="Test finding") -> StoredFinding:
    return StoredFinding(
        id="FND-1",
        engagement_id="E",
        scan_job_id="J1",
        rule_id=rule_id,
        fingerprint="fp1",
        title=title,
        category="acl",
        severity=severity,
        confidence=Confidence.HIGH,
        status=FindingStatus.OPEN,
        affected_assets=["CN=Alice,DC=corp,DC=example"],
        description="Description avec IP 10.0.0.5 et email alice@corp.example",
        technical_details="password=hunter2 dans les details",
        impact="impact",
        validation_procedure="validation",
        remediation="remediation",
        references=["https://example.com"],
        mitre_technique_id=None,
        first_seen="2026-01-01T00:00:00+00:00",
        last_seen="2026-01-02T00:00:00+00:00",
        evidence=[
            StoredEvidence(
                id="EV-1",
                source="ldap",
                timestamp="2026-01-01T00:00:00+00:00",
                object_type="user",
                object_id="CN=Alice",
                attribute="attr",
                value="secret=abc123",
                hash="a" * 64,
                collector_version="0.2.0",
            )
        ],
    )


def test_sanitize_text_masks_ip_email_and_secrets() -> None:
    text = "IP 10.0.0.5, email alice@corp.example, password=hunter2"
    out = sanitize_text(text)
    assert "10.0.0.5" not in out
    assert "alice@corp.example" not in out
    assert "hunter2" not in out
    assert "[IP MASQUEE]" in out
    assert "[EMAIL MASQUE]" in out


def test_build_report_data_sanitizes_when_requested() -> None:
    engagement = Engagement(id="ENG-1", client_id="C1", name="ENG-1")
    data = build_report_data(
        kind="technical",
        engagement=engagement,
        client_name="ACME",
        scope_summary=["domain: x"],
        limitations=[],
        findings=[_finding()],
        attack_paths=[],
        sanitize=True,
    )
    assert data.sanitized is True
    assert "10.0.0.5" not in data.findings[0].description
    assert "hunter2" not in data.findings[0].technical_details
    assert "abc123" not in data.findings[0].evidence[0].value


def test_build_report_data_counts_by_severity() -> None:
    engagement = Engagement(id="ENG-1", client_id="C1", name="ENG-1")
    findings = [_finding(severity=Severity.CRITICAL), _finding(severity=Severity.HIGH)]
    data = build_report_data(
        kind="executive",
        engagement=engagement,
        client_name="ACME",
        scope_summary=[],
        limitations=[],
        findings=findings,
        attack_paths=[],
        sanitize=False,
    )
    assert data.counts_by_severity["critical"] == 1
    assert data.counts_by_severity["high"] == 1
    assert data.counts_by_severity["medium"] == 0


def test_render_executive_markdown_contains_key_sections() -> None:
    engagement = Engagement(id="ENG-1", client_id="C1", name="ENG-1")
    data = build_report_data(
        kind="executive",
        engagement=engagement,
        client_name="ACME",
        scope_summary=["domain: x"],
        limitations=["limite 1"],
        findings=[_finding()],
        attack_paths=[],
        sanitize=False,
    )
    md = render_executive_markdown(data)
    assert "# Rapport executif" in md
    assert "ACME" in md
    assert "limite 1" in md
    assert "[HIGH]" in md


def test_render_technical_markdown_includes_evidence_and_full_details() -> None:
    engagement = Engagement(id="ENG-1", client_id="C1", name="ENG-1")
    data = build_report_data(
        kind="technical",
        engagement=engagement,
        client_name="ACME",
        scope_summary=[],
        limitations=[],
        findings=[_finding()],
        attack_paths=[],
        sanitize=False,
    )
    md = render_technical_markdown(data)
    assert "AD-ACL-001" in md
    assert "Procedure de validation" in md
    assert "a" * 12 in md  # prefixe du hash de preuve


def test_render_html_escapes_content() -> None:
    engagement = Engagement(id="ENG-1", client_id="C1", name="ENG-1")
    finding = _finding(title="<script>alert(1)</script>")
    data = build_report_data(
        kind="executive",
        engagement=engagement,
        client_name="ACME",
        scope_summary=[],
        limitations=[],
        findings=[finding],
        attack_paths=[],
        sanitize=False,
    )
    html = render_executive_html(data)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_technical_html_well_formed() -> None:
    engagement = Engagement(id="ENG-1", client_id="C1", name="ENG-1")
    data = build_report_data(
        kind="technical",
        engagement=engagement,
        client_name="ACME",
        scope_summary=[],
        limitations=[],
        findings=[_finding()],
        attack_paths=[],
        sanitize=False,
    )
    html = render_technical_html(data)
    assert html.startswith("<!DOCTYPE html>")
    assert "</html>" in html


def test_json_export_dict_shape() -> None:
    rows = findings_to_dicts([_finding()])
    assert rows[0]["severity"] == "high"
    assert rows[0]["status"] == "open"
    assert rows[0]["rule_id"] == "AD-ACL-001"


def test_csv_export_has_header_and_row() -> None:
    text = findings_to_csv_text([_finding()])
    lines = text.strip().splitlines()
    assert lines[0].startswith("id,rule_id,title")
    assert "AD-ACL-001" in lines[1]


def test_compute_diff_detects_new_and_resolved() -> None:
    baseline = Baseline(
        id="BASE-1",
        engagement_id="E",
        label="l",
        created_at="t",
        finding_fingerprints={"fp-old", "fp-common"},
        object_counts={"users": 5, "findings": 2},
    )
    current = [
        _finding(),
    ]
    current[0].fingerprint = "fp-common"
    new_finding = _finding()
    new_finding.fingerprint = "fp-new"
    current.append(new_finding)

    result = compute_diff(baseline, current, {"users": 7, "findings": 2})
    assert [f.fingerprint for f in result.new_findings] == ["fp-new"]
    assert result.resolved_fingerprints == ["fp-old"]
    assert result.unchanged_count == 1
    assert result.object_count_deltas == {"users": 2}


def test_compute_diff_no_changes() -> None:
    baseline = Baseline(
        id="BASE-1",
        engagement_id="E",
        label="l",
        created_at="t",
        finding_fingerprints={"fp-common"},
        object_counts={"users": 5},
    )
    current = [_finding()]
    current[0].fingerprint = "fp-common"
    result = compute_diff(baseline, current, {"users": 5})
    assert result.new_findings == []
    assert result.resolved_fingerprints == []
    assert result.object_count_deltas == {}
