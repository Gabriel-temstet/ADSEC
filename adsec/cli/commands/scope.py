"""Commandes `adsec scope ...`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import print_error, print_success, print_table
from adsec.core.models.engagement import ScopeEntry
from adsec.core.models.enums import ScopeEntryType
from adsec.core.scope.scope_manager import ScopeManager
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.scopes import ScopeRepository

app = typer.Typer(help="Gestion du scope d'un engagement.")

_TYPE_MAP = {
    "domain": ScopeEntryType.DOMAIN,
    "host": ScopeEntryType.HOST_INCLUDE,
    "host-exclude": ScopeEntryType.HOST_EXCLUDE,
    "network": ScopeEntryType.NETWORK_INCLUDE,
    "network-exclude": ScopeEntryType.NETWORK_EXCLUDE,
}


@app.command("add")
def add_scope_entry(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    entry_type: str = typer.Argument(..., help=f"Type d'entree: {', '.join(_TYPE_MAP)}"),
    value: str = typer.Argument(..., help="Valeur (domaine, host/glob, ou CIDR)"),
) -> None:
    """Ajoute une entree au scope d'un engagement."""
    if entry_type not in _TYPE_MAP:
        print_error(
            f"Type d'entree invalide: {entry_type!r}. Valeurs possibles: {', '.join(_TYPE_MAP)}"
        )
        raise typer.Exit(code=1)

    ctx = get_context()
    conn = ctx.database.connection
    engagement_repo = EngagementRepository(conn)
    scope_repo = ScopeRepository(conn)

    try:
        eng = engagement_repo.resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    try:
        entry = ScopeEntry(engagement_id=eng.id, entry_type=_TYPE_MAP[entry_type], value=value)
    except ValueError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    scope_repo.add(entry)
    print_success(f"Ajoute au scope de {eng.name}: [{entry_type}] {value}")


@app.command("show")
def show_scope(engagement: str = typer.Argument(..., help="ID ou nom de l'engagement")) -> None:
    """Affiche le scope complet d'un engagement."""
    ctx = get_context()
    conn = ctx.database.connection
    engagement_repo = EngagementRepository(conn)
    scope_repo = ScopeRepository(conn)

    try:
        eng = engagement_repo.resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    entries = scope_repo.list_for_engagement(eng.id)
    if not entries:
        print_error("Scope vide pour cet engagement.")
        return
    print_table(
        f"Scope - {eng.name}",
        ["Type", "Valeur"],
        [[e.entry_type.value, e.value] for e in entries],
    )


@app.command("test")
def test_scope(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    target: str = typer.Argument(..., help="Cible a tester (host, FQDN ou IP)"),
) -> None:
    """Teste si une cible serait consideree en scope pour cet engagement."""
    ctx = get_context()
    conn = ctx.database.connection
    engagement_repo = EngagementRepository(conn)
    scope_repo = ScopeRepository(conn)

    try:
        eng = engagement_repo.resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    scope = scope_repo.build_scope(eng.id)
    decision = ScopeManager(scope).evaluate(target)
    status = "EN SCOPE" if decision.in_scope else "HORS SCOPE"
    print_table(
        "Test de scope",
        ["Cible", "Resultat", "Raison"],
        [[decision.target, status, decision.reason]],
    )
