"""Construction homogene des findings : chaque finding explique pourquoi il
a ete detecte, pourquoi il est considere comme risque, ce qui pourrait en
faire un faux positif et comment le verifier (exigence du produit)."""

from __future__ import annotations

from adsec.core.models.enums import Confidence, Severity
from adsec.rules.base import EvidenceRef, Finding


def new_finding(
    *,
    rule_id: str,
    category: str,
    title: str,
    severity: Severity,
    confidence: Confidence,
    description: str,
    why_detected: str,
    why_risky: str,
    false_positive: str,
    impact: str,
    validation: str,
    remediation: str,
    assets: list[str],
    principal: str,
    condition_key: str,
    evidence: list[EvidenceRef],
    references: list[str],
    mitre_technique_id: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        description=description,
        technical_details=(
            f"Pourquoi detecte : {why_detected} "
            f"Pourquoi risque : {why_risky} "
            f"Faux positif possible : {false_positive}"
        ),
        impact=impact,
        validation_procedure=validation,
        remediation=remediation,
        affected_assets=assets,
        principal=principal,
        condition_key=condition_key,
        evidence=evidence,
        references=references,
        mitre_technique_id=mitre_technique_id,
    )
