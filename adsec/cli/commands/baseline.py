"""Commandes `adsec baseline ...`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import print_error, print_success, print_table
from adsec.database.repositories.baseline import BaselineRepository
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.findings import FindingRepository
from adsec.reporting.limitations import compute_object_counts

app = typer.Typer(help="Gestion des baselines (pour 'adsec diff').")


@app.command("create")
def create_baseline(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    label: str = typer.Option(None, "--label", help="Libelle (defaut: horodatage)"),
) -> None:
    """Capture un instantane de l'etat courant (findings + compteurs d'objets)."""
    ctx = get_context()
    conn = ctx.database.connection
    try:
        eng = EngagementRepository(conn).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    findings = FindingRepository(conn).list(eng.id)
    fingerprints = {f.fingerprint for f in findings}
    counts = compute_object_counts(conn, eng.id)
    baseline = BaselineRepository(conn).create(eng.id, label or "baseline", fingerprints, counts)
    print_success(f"Baseline {baseline.id} creee ({len(fingerprints)} finding(s), {counts}).")


@app.command("list")
def list_baselines(engagement: str = typer.Argument(..., help="ID ou nom de l'engagement")) -> None:
    """Liste les baselines d'un engagement."""
    ctx = get_context()
    conn = ctx.database.connection
    try:
        eng = EngagementRepository(conn).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    baselines = BaselineRepository(conn).list(eng.id)
    if not baselines:
        print_error("Aucune baseline.")
        return
    print_table(
        f"Baselines - {eng.name}",
        ["ID", "Libelle", "Cree le", "Findings"],
        [[b.id, b.label, b.created_at, str(len(b.finding_fingerprints))] for b in baselines],
    )
