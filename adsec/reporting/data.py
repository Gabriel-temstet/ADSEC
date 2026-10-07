"""Structure de donnees commune aux rapports executif et technique, rendue
ensuite en Markdown, HTML, JSON ou CSV par les modules de ce package."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from adsec.core.models.engagement import Engagement
from adsec.core.models.enums import Severity
from adsec.database.repositories.findings import StoredFinding
from adsec.graph.models import AttackPath
from adsec.reporting.sanitizer import sanitize_text

_SEVERITY_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]


@dataclass
class ReportData:
    kind: str  # "executive" | "technical"
    engagement_name: str
    client_name: str
    generated_at: str
    scope_summary: list[str]
    limitations: list[str]
    counts_by_severity: dict[str, int]
    findings: list[StoredFinding]
    attack_path_highlights: list[AttackPath]
    sanitized: bool
    methodology: str = (
        "Audit non-destructif realise avec adsec : decouverte et collecte LDAP, "
        "analyse des ACL/GPO/Kerberos/trusts, tests SMB/DNS en lecture seule, "
        "calcul de chemins d'attaque. Aucune action intrusive n'a ete executee."
    )


def _apply_sanitization(findings: list[StoredFinding], sanitize: bool) -> list[StoredFinding]:
    if not sanitize:
        return findings
    sanitized = []
    for f in findings:
        clone = f.__class__(**f.__dict__)
        clone.description = sanitize_text(f.description)
        clone.technical_details = sanitize_text(f.technical_details)
        clone.affected_assets = [sanitize_text(a) for a in f.affected_assets]
        clone.evidence = [
            e.__class__(
                **{
                    **e.__dict__,
                    "value": sanitize_text(e.value),
                    "object_id": sanitize_text(e.object_id),
                }
            )
            for e in f.evidence
        ]
        sanitized.append(clone)
    return sanitized


def build_report_data(
    *,
    kind: str,
    engagement: Engagement,
    client_name: str,
    scope_summary: list[str],
    limitations: list[str],
    findings: list[StoredFinding],
    attack_paths: list[AttackPath],
    sanitize: bool = False,
) -> ReportData:
    findings = _apply_sanitization(findings, sanitize)
    counts = dict.fromkeys((s.value for s in _SEVERITY_ORDER), 0)
    for f in findings:
        counts[f.severity.value] = counts.get(f.severity.value, 0) + 1

    highlights = sorted(attack_paths, key=lambda p: p.length)[:10]

    return ReportData(
        kind=kind,
        engagement_name=engagement.name,
        client_name=client_name,
        generated_at=datetime.now(UTC).isoformat(),
        scope_summary=scope_summary,
        limitations=limitations,
        counts_by_severity=counts,
        findings=findings,
        attack_path_highlights=highlights,
        sanitized=sanitize,
    )
