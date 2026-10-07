"""Commande `adsec diff`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import console, print_error, print_table
from adsec.database.repositories.baseline import BaselineRepository
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.findings import FindingRepository
from adsec.reporting.diff import compute_diff
from adsec.reporting.limitations import compute_object_counts

app = typer.Typer(help="Comparaison de l'etat courant a une baseline.")


@app.callback(invoke_without_command=True)
def diff(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    baseline_id: str = typer.Option(
        None, "--baseline", help="ID de baseline (defaut: la plus recente)"
    ),
) -> None:
    """Affiche NEW/RESOLVED findings et les deltas d'objets depuis une baseline."""
    ctx = get_context()
    conn = ctx.database.connection
    try:
        eng = EngagementRepository(conn).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    repo = BaselineRepository(conn)
    baseline = repo.get(baseline_id) if baseline_id else repo.get_latest(eng.id)
    if baseline is None:
        print_error("Aucune baseline. Creez-en une avec 'adsec baseline create' d'abord.")
        raise typer.Exit(code=1)

    current_findings = FindingRepository(conn).list(eng.id)
    current_counts = compute_object_counts(conn, eng.id)
    result = compute_diff(baseline, current_findings, current_counts)

    console.print(
        f"Diff depuis la baseline {baseline.id} ({baseline.label}, {baseline.created_at})"
    )
    console.print(
        f"  {len(result.new_findings)} NOUVEAU(X), {len(result.resolved_fingerprints)} "
        f"RESOLU(S), {result.unchanged_count} inchange(s)"
    )

    if result.new_findings:
        print_table(
            "NOUVEAUX findings",
            ["Regle", "Severite", "Titre"],
            [[f.rule_id, f.severity.value, f.title] for f in result.new_findings],
        )
    if result.resolved_fingerprints:
        console.print(
            f"  Findings resolus (fingerprints) : {', '.join(f[:12] for f in result.resolved_fingerprints)}"
        )
    if result.object_count_deltas:
        print_table(
            "Deltas d'objets",
            ["Type", "Delta"],
            [[k, f"{v:+d}"] for k, v in sorted(result.object_count_deltas.items())],
        )
