from __future__ import annotations

from adsec.core.models.enums import Confidence, RelationConfidence, Severity
from adsec.graph.correlation import correlate
from adsec.graph.models import AttackPath, GraphEdge, RelationType
from adsec.rules.base import Finding
from adsec.rules.risk import ExploitabilityLevel, ImpactLevel, assess_risk


def _finding(rule_id: str, principal: str, affected: list[str]) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="t",
        category="acl",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="d",
        technical_details="td",
        impact="i",
        validation_procedure="v",
        remediation="r",
        affected_assets=affected,
        principal=principal,
    )


def _path(
    source: str, target: str, first_relation: RelationType, first_target: str, length: int = 1
) -> AttackPath:
    edges = [
        GraphEdge(
            source_id=source,
            target_id=first_target,
            relation=first_relation,
            confidence=RelationConfidence.CONFIRMED,
        )
    ]
    for _ in range(length - 1):
        edges.append(
            GraphEdge(
                source_id=first_target,
                target_id=target,
                relation=RelationType.MEMBER_OF,
                confidence=RelationConfidence.CONFIRMED,
            )
        )
    return AttackPath(
        engagement_id="E",
        source_id=source,
        target_id=target,
        node_ids=[source, target],
        edges=edges,
        length=len(edges),
        confidence=RelationConfidence.CONFIRMED,
    )


def test_correlation_matches_exact_target() -> None:
    finding = _finding("AD-ACL-001", "S-1-1", ["CN=Alice"])
    sid_to_dn = {"S-1-1": "CN=HelpDesk"}
    matching_path = _path("CN=HelpDesk", "CN=DA", RelationType.CAN_CONTROL, "CN=Alice")
    other_path = _path("CN=HelpDesk", "CN=DA", RelationType.CAN_CONTROL, "CN=Bob")

    result = correlate([("FND-1", finding)], [matching_path, other_path], sid_to_dn)
    assert len(result) == 1
    assert result[0].path_index == 0  # uniquement le chemin qui passe par Alice


def test_correlation_ignores_wrong_relation() -> None:
    finding = _finding("AD-ACL-003", "S-1-1", ["CN=Alice"])  # attend CAN_RESET_PASSWORD
    sid_to_dn = {"S-1-1": "CN=Svc"}
    path = _path("CN=Svc", "CN=DA", RelationType.CAN_CONTROL, "CN=Alice")  # mauvaise relation
    assert correlate([("FND-1", finding)], [path], sid_to_dn) == []


def test_correlation_dcsync_ignores_target_mismatch() -> None:
    # AD-ACL-005 : affected_assets contient le naming context, pas le fqdn du noeud domaine.
    finding = _finding("AD-ACL-005", "S-1-1", ["DC=corp,DC=example"])
    sid_to_dn = {"S-1-1": "CN=Bob"}
    path = _path("CN=Bob", "corp.example", RelationType.CAN_DCSYNC, "corp.example")
    result = correlate([("FND-1", finding)], [path], sid_to_dn)
    assert len(result) == 1


def test_correlation_unmapped_rule_never_matches() -> None:
    finding = _finding("AD-KRB-001", "S-1-1", ["CN=Alice"])
    path = _path("CN=Alice", "CN=DA", RelationType.MEMBER_OF, "CN=DA")
    assert correlate([("FND-1", finding)], [path], {}) == []


def test_correlation_requires_principal() -> None:
    finding = _finding("AD-ACL-001", "", ["CN=Alice"])
    path = _path("", "CN=DA", RelationType.CAN_CONTROL, "CN=Alice")
    assert correlate([("FND-1", finding)], [path], {}) == []


def test_assess_risk_base_profile_no_paths() -> None:
    risk = assess_risk("AD-KRB-001", Severity.MEDIUM, Confidence.HIGH, [])
    assert risk.impact == ImpactLevel.LOCAL
    assert risk.exploitability == ExploitabilityLevel.TRIVIAL
    assert risk.exposure == 0
    assert "Aucun chemin d'attaque correle" in risk.explanation[-1]


def test_assess_risk_upgrades_impact_when_correlated() -> None:
    path = _path("CN=HelpDesk", "corp.example", RelationType.CAN_CONTROL, "CN=Alice")
    risk = assess_risk("AD-ACL-001", Severity.HIGH, Confidence.HIGH, [path])
    assert risk.impact == ImpactLevel.DOMAIN_WIDE  # releve depuis LATERAL
    assert risk.exposure == 1
    assert "releve de lateral a domain_wide" in risk.explanation[-1]
    assert "corp.example" in risk.reachable_targets


def test_assess_risk_domain_wide_stays_domain_wide_with_paths() -> None:
    path = _path("CN=Bob", "corp.example", RelationType.CAN_DCSYNC, "corp.example")
    risk = assess_risk("AD-ACL-005", Severity.CRITICAL, Confidence.HIGH, [path])
    assert risk.impact == ImpactLevel.DOMAIN_WIDE
    assert "confirme par" in risk.explanation[-1]


def test_assess_risk_unknown_rule_uses_default_profile() -> None:
    risk = assess_risk("AD-UNKNOWN-999", Severity.LOW, Confidence.LOW, [])
    assert risk.impact == ImpactLevel.LOCAL
    assert risk.exploitability == ExploitabilityLevel.REQUIRES_ACCESS


def test_assess_risk_never_overwrites_severity_or_confidence() -> None:
    risk = assess_risk("AD-ACL-001", Severity.HIGH, Confidence.MEDIUM, [])
    assert risk.severity == Severity.HIGH
    assert risk.confidence == Confidence.MEDIUM
