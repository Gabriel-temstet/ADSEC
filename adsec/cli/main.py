"""Point d'entree de la CLI `adsec`."""

from __future__ import annotations

import typer

from adsec import __version__
from adsec.cli.commands import (
    baseline,
    client,
    diff,
    doctor,
    engagement,
    export,
    findings,
    graph,
    report,
    scan,
    scope,
)
from adsec.cli.context import get_context
from adsec.logging_setup import configure_logging

app = typer.Typer(
    name="adsec",
    help="Plateforme professionnelle d'audit et de pentest Active Directory (safe-by-default).",
    no_args_is_help=True,
)

app.add_typer(client.app, name="client")
app.add_typer(engagement.app, name="engagement")
app.add_typer(scope.app, name="scope")
app.add_typer(doctor.app, name="doctor")
app.add_typer(scan.app, name="scan")
app.add_typer(findings.app, name="findings")
app.add_typer(graph.app, name="graph")
app.add_typer(export.app, name="export")
app.add_typer(report.app, name="report")
app.add_typer(baseline.app, name="baseline")
app.add_typer(diff.app, name="diff")


@app.callback()
def main(
    log_level: str = typer.Option(None, "--log-level", help="DEBUG, INFO, WARNING, ERROR"),
    log_format: str = typer.Option(None, "--log-format", help="json ou console"),
) -> None:
    """Initialise la configuration et le logging avant toute commande."""
    ctx = get_context()
    configure_logging(
        level=log_level or ctx.settings.log_level,
        fmt=log_format or ctx.settings.log_format,
    )


@app.command("version")
def version() -> None:
    """Affiche la version d'ADSEC."""
    typer.echo(f"adsec {__version__}")


if __name__ == "__main__":
    app()
