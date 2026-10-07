"""AD-SEC-000 : verifie que l'engagement est configure en posture safe par
defaut (aucune action intrusive activee sans decision explicite).

Ce controle ne depend d'aucune collecte AD : il valide la configuration de
l'engagement lui-meme, ce qui le rend utilisable des la Phase 2 et permet de
valider de bout en bout le plugin system avant l'arrivee des collectors.
"""

from __future__ import annotations

from typing import ClassVar

from adsec.core.models.enums import AccessLevel, Confidence, Severity
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext


class SafePostureCheck(CheckPlugin):
    id = "AD-SEC-000"
    name = "Posture safe-by-default de l'engagement"
    version = "1.0.0"
    category = "security"
    description = (
        "Verifie que les actions intrusives ne sont pas activees sans "
        "decision explicite dans le scope de l'engagement."
    )
    severity_hint = Severity.HIGH
    required_permissions = AccessLevel.ANONYMOUS
    protocols: ClassVar[list[str]] = []
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [
            DataRequirement(
                kind="engagement_config",
                description="Configuration de scope de l'engagement (intrusive_actions_enabled)",
            )
        ]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        rows = data.get("engagement_config")
        if not rows:
            return []

        config = rows[0]
        intrusive_enabled = bool(config.get("intrusive_actions_enabled", False))
        if not intrusive_enabled:
            return []

        finding = Finding(
            rule_id=self.id,
            title="Actions intrusives activees sur l'engagement",
            category=self.category,
            severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            description=(
                "Le scope de cet engagement autorise explicitement les actions "
                "intrusives (intrusive_actions_enabled=true). Ce mode sort du "
                "comportement SAFE par defaut d'ADSEC."
            ),
            technical_details=(
                "La configuration de scope lue pour l'engagement "
                f"{ctx.engagement_id!r} contient intrusive_actions_enabled=true."
            ),
            impact=(
                "Des plugins marques intrusifs pourraient etre executes lors "
                "des prochains scans, avec un risque de modification de "
                "l'environnement audite."
            ),
            validation_procedure=(
                "Verifier avec l'operateur et le ROE de mission que ce mode a "
                "ete active en connaissance de cause pour cet engagement."
            ),
            remediation=(
                "Repasser intrusive_actions_enabled a false si l'activation "
                "n'etait pas intentionnelle, ou documenter la decision dans "
                "le ROE."
            ),
            affected_assets=[ctx.engagement_id],
        )
        return [finding]
