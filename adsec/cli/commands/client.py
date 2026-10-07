"""Commandes `adsec client ...`."""

from __future__ import annotations

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import print_error, print_success, print_table
from adsec.core.models.engagement import Client
from adsec.database.repositories.clients import ClientAlreadyExistsError, ClientRepository

app = typer.Typer(help="Gestion des clients du cabinet.")


@app.command("create")
def create_client(name: str = typer.Argument(..., help="Nom du client, ex: ACME")) -> None:
    """Cree un nouveau client."""
    ctx = get_context()
    repo = ClientRepository(ctx.database.connection)
    try:
        client = repo.create(Client(name=name))
    except (ClientAlreadyExistsError, ValueError) as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc
    print_success(f"Client cree: {client.name} ({client.id})")


@app.command("list")
def list_clients() -> None:
    """Liste tous les clients."""
    ctx = get_context()
    repo = ClientRepository(ctx.database.connection)
    clients = repo.list_all()
    if not clients:
        print_error("Aucun client enregistre.")
        return
    print_table(
        "Clients",
        ["ID", "Nom", "Cree le"],
        [[c.id, c.name, c.created_at.isoformat()] for c in clients],
    )
