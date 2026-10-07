"""Commandes `adsec export ...`."""

from __future__ import annotations

from pathlib import Path

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import print_error, print_success
from adsec.database.repositories.acl import AclRepository
from adsec.database.repositories.directory import DirectoryRepository, GpoRepository
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.topology import TopologyRepository
from adsec.export.bloodhound import build_export, write_bloodhound_export
from adsec.graph.builder import build_graph

app = typer.Typer(help="Export des donnees collectees vers des formats externes.")


@app.command("bloodhound")
def export_bloodhound(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    output: Path = typer.Option(  # noqa: B008
        None,
        "--output",
        help="Repertoire de sortie (defaut: <data_dir>/reports/<engagement>/bloodhound)",
    ),
) -> None:
    """Exporte users/groups/computers/domains/gpos/relationships au format
    BloodHound-compatible (6 fichiers JSON)."""
    ctx = get_context()
    conn = ctx.database.connection
    try:
        eng = EngagementRepository(conn).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    topology = TopologyRepository(conn)
    directory = DirectoryRepository(conn)
    gpo_repo = GpoRepository(conn)

    domains = topology.list_domains(eng.id)
    if not domains:
        print_error("Aucune donnee collectee : lancez 'adsec scan run' d'abord.")
        raise typer.Exit(code=1)
    domain = domains[0]

    users = directory.list_users(eng.id)
    groups = directory.list_groups(eng.id)
    computers = directory.list_computers(eng.id)
    gpos = gpo_repo.list_gpos(eng.id)

    graph = build_graph(
        users=[u.model_dump() for u in users],
        groups=[g.model_dump() for g in groups],
        computers=[c.model_dump() for c in computers],
        memberships=[m.model_dump() for m in directory.list_all_memberships(eng.id)],
        acls=[a.model_dump() for a in AclRepository(conn).list_acls(eng.id)],
        gpos=[g.model_dump() for g in gpos],
        domain_fqdn=domain.fqdn,
    )

    export = build_export(
        graph=graph, users=users, groups=groups, computers=computers, domain=domain, gpos=gpos
    )

    output_dir = output or (ctx.settings.reports_dir / eng.id / "bloodhound")
    paths = write_bloodhound_export(export, output_dir)
    print_success(f"Export BloodHound-compatible ecrit dans {output_dir}")
    for path in paths:
        typer.echo(f"  {path}")
