"""Commandes `adsec engagement ...`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import print_error, print_success, print_table
from adsec.core.models.engagement import Engagement
from adsec.core.models.enums import ScanProfile
from adsec.database.repositories.clients import ClientRepository
from adsec.database.repositories.engagements import (
    EngagementAlreadyExistsError,
    EngagementNotFoundError,
    EngagementRepository,
)

app = typer.Typer(help="Gestion des engagements (missions).")


@app.command("create")
def create_engagement(
    client_name: str = typer.Argument(..., help="Nom du client (deja cree)"),
    name: str = typer.Argument(..., help="Nom de l'engagement, ex: ACME-2026-001"),
    roe_reference: str = typer.Option(None, "--roe", help="Reference du ROE de mission"),
    operator: str = typer.Option(None, "--operator", help="Operateur/pentester responsable"),
    profile: ScanProfile = typer.Option(  # noqa: B008 - pattern standard Typer
        ScanProfile.SAFE, "--profile", help="Profil de scan par defaut"
    ),
) -> None:
    """Cree un nouvel engagement pour un client existant."""
    ctx = get_context()
    conn = ctx.database.connection
    client_repo = ClientRepository(conn)
    engagement_repo = EngagementRepository(conn)

    client = client_repo.get_by_name(client_name)
    if client is None:
        print_error(
            f"Client introuvable: {client_name!r}. Creez-le d'abord avec 'adsec client create'."
        )
        raise typer.Exit(code=1)

    try:
        engagement = engagement_repo.create(
            Engagement(
                client_id=client.id,
                name=name,
                roe_reference=roe_reference,
                operator=operator or ctx.settings.default_operator,
                default_profile=profile,
            )
        )
    except (EngagementAlreadyExistsError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    print_success(f"Engagement cree: {engagement.name} ({engagement.id})")


@app.command("list")
def list_engagements(client_name: str = typer.Argument(..., help="Nom du client")) -> None:
    """Liste les engagements d'un client."""
    ctx = get_context()
    conn = ctx.database.connection
    client_repo = ClientRepository(conn)
    engagement_repo = EngagementRepository(conn)

    client = client_repo.get_by_name(client_name)
    if client is None:
        print_error(f"Client introuvable: {client_name!r}")
        raise typer.Exit(code=1)

    engagements = engagement_repo.list_for_client(client.id)
    if not engagements:
        print_error("Aucun engagement pour ce client.")
        return
    print_table(
        f"Engagements - {client.name}",
        ["ID", "Nom", "Statut", "Profil", "Cree le"],
        [
            [e.id, e.name, e.status.value, e.default_profile.value, e.created_at.isoformat()]
            for e in engagements
        ],
    )


@app.command("show")
def show_engagement(
    identifier: str = typer.Argument(..., help="ID ou nom de l'engagement"),
) -> None:
    """Affiche le detail d'un engagement."""
    ctx = get_context()
    engagement_repo = EngagementRepository(ctx.database.connection)
    try:
        engagement = engagement_repo.resolve(identifier)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    print_table(
        f"Engagement {engagement.name}",
        ["Champ", "Valeur"],
        [
            ["id", engagement.id],
            ["client_id", engagement.client_id],
            ["statut", engagement.status.value],
            ["profil par defaut", engagement.default_profile.value],
            ["ROE", engagement.roe_reference or "-"],
            ["operateur", engagement.operator or "-"],
            ["cree le", engagement.created_at.isoformat()],
        ],
    )
