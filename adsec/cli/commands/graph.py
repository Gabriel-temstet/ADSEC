"""Commandes `adsec graph ...`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import console, print_error, print_table
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.graph import AttackPathRepository

app = typer.Typer(help="Consultation des chemins d'attaque calcules (profil 'deep').")


@app.command("targets")
def list_targets(engagement: str = typer.Argument(..., help="ID ou nom de l'engagement")) -> None:
    """Liste les actifs critiques pour lesquels des chemins ont ete calcules."""
    ctx = get_context()
    try:
        eng = EngagementRepository(ctx.database.connection).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    repo = AttackPathRepository(ctx.database.connection)
    targets = repo.list_targets(eng.id)
    if not targets:
        print_error(
            "Aucun chemin d'attaque calcule. Lancez 'adsec scan run --profile deep' d'abord."
        )
        return
    for target in targets:
        count = len(repo.list_for_target(eng.id, target))
        console.print(f"  {target}  ({count} chemin(s))")


@app.command("show")
def show_paths(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    target: str = typer.Argument(..., help="DN de l'actif critique (voir 'adsec graph targets')"),
    limit: int = typer.Option(10, "--limit", help="Nombre maximum de chemins affiches"),
) -> None:
    """Affiche les chemins les plus courts/fiables vers un actif critique."""
    ctx = get_context()
    try:
        eng = EngagementRepository(ctx.database.connection).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    repo = AttackPathRepository(ctx.database.connection)
    paths = repo.list_for_target(eng.id, target)
    if not paths:
        print_error(f"Aucun chemin connu vers {target!r}.")
        raise typer.Exit(code=1)

    print_table(
        f"Chemins vers {target}",
        ["Source", "Longueur", "Confiance", "Resume"],
        [[p.source_id, str(p.length), p.confidence.value, p.impact_summary] for p in paths[:limit]],
    )
    if len(paths) > limit:
        console.print(
            f"  ... et {len(paths) - limit} autre(s) chemin(s) (--limit pour en voir plus)"
        )
