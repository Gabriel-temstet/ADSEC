"""Commandes `adsec findings ...`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import console, print_error, print_success, print_table
from adsec.core.models.enums import FindingStatus, Severity
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.findings import FindingRepository
from adsec.database.repositories.graph import AttackPathRepository
from adsec.rules.risk import assess_risk

app = typer.Typer(help="Consultation et suivi des findings.")


def _resolve_engagement(identifier: str):  # type: ignore[no-untyped-def]
    ctx = get_context()
    try:
        return ctx, EngagementRepository(ctx.database.connection).resolve(identifier)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc


@app.command("list")
def list_findings(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    rule: str = typer.Option(None, "--rule", help="Filtrer par identifiant de regle"),
    severity: Severity = typer.Option(None, "--severity", help="Filtrer par severite"),  # noqa: B008
) -> None:
    """Liste les findings d'un engagement (tries par severite)."""
    ctx, eng = _resolve_engagement(engagement)
    findings = FindingRepository(ctx.database.connection).list(eng.id, rule, severity)
    if not findings:
        print_error("Aucun finding.")
        return
    print_table(
        f"Findings - {eng.name}",
        ["ID", "Regle", "Severite", "Confiance", "Statut", "Titre"],
        [
            [
                f.id,
                f.rule_id,
                f.severity.value,
                f.confidence.value,
                f.status.value,
                f.title,
            ]
            for f in findings
        ],
    )


@app.command("show")
def show_finding(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    finding: str = typer.Argument(..., help="ID ou prefixe d'ID/fingerprint du finding"),
) -> None:
    """Affiche le detail complet d'un finding, preuves comprises."""
    ctx, eng = _resolve_engagement(engagement)
    stored = FindingRepository(ctx.database.connection).find(eng.id, finding)
    if stored is None:
        print_error(f"Finding introuvable ou identifiant ambigu: {finding!r}")
        raise typer.Exit(code=1)

    console.print(f"[bold]{stored.rule_id}[/bold] - {stored.title}", markup=True)
    print_table(
        "Synthese",
        ["Champ", "Valeur"],
        [
            ["id", stored.id],
            ["severite", stored.severity.value],
            ["confiance", stored.confidence.value],
            ["statut", stored.status.value],
            ["actifs concernes", ", ".join(stored.affected_assets)],
            ["premiere observation", stored.first_seen],
            ["derniere observation", stored.last_seen],
            ["MITRE ATT&CK", stored.mitre_technique_id or "aucun mapping fiable"],
        ],
    )
    for label, text in (
        ("Description", stored.description),
        ("Details techniques", stored.technical_details),
        ("Impact", stored.impact),
        ("Procedure de validation", stored.validation_procedure),
        ("Remediation", stored.remediation),
    ):
        console.print(f"\n[bold]{label}[/bold]\n{text}", markup=True, highlight=False)
    if stored.references:
        console.print("\n[bold]References[/bold]", markup=True)
        for ref in stored.references:
            console.print(f"  - {ref}", markup=False)
    if stored.evidence:
        print_table(
            "Preuves",
            ["Source", "Objet", "Attribut", "Valeur", "Hash"],
            [[e.source, e.object_id, e.attribute, e.value, e.hash[:12]] for e in stored.evidence],
        )

    linked_paths = AttackPathRepository(ctx.database.connection).list_paths_for_finding(stored.id)
    risk = assess_risk(stored.rule_id, stored.severity, stored.confidence, linked_paths)
    print_table(
        "Modele de risque (dimensions separees)",
        ["Facteur", "Valeur"],
        [
            ["severite", risk.severity.value],
            ["confiance", risk.confidence.value],
            ["impact", risk.impact.value],
            ["exploitabilite", risk.exploitability.value],
            ["exposition (chemins d'attaque)", str(risk.exposure)],
        ],
    )
    console.print("\n[bold]Pourquoi ces valeurs[/bold]", markup=True)
    for line in risk.explanation:
        console.print(f"  - {line}", markup=False)

    if linked_paths:
        print_table(
            "Chemins d'attaque correles",
            ["Source", "Cible", "Longueur", "Confiance"],
            [[p.source_id, p.target_id, str(p.length), p.confidence.value] for p in linked_paths],
        )


@app.command("status")
def set_status(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    finding: str = typer.Argument(..., help="ID ou prefixe du finding"),
    status: FindingStatus = typer.Argument(  # noqa: B008
        ..., help="open|confirmed|false_positive|accepted_risk|remediated"
    ),
) -> None:
    """Change le statut d'un finding (preserve lors des re-scans)."""
    ctx, eng = _resolve_engagement(engagement)
    repo = FindingRepository(ctx.database.connection)
    stored = repo.find(eng.id, finding)
    if stored is None:
        print_error(f"Finding introuvable ou identifiant ambigu: {finding!r}")
        raise typer.Exit(code=1)
    repo.set_status(eng.id, stored.id, status)
    print_success(f"{stored.id} -> {status.value}")
