"""Commande `adsec report generate`."""

from __future__ import annotations

from pathlib import Path

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import print_error, print_success
from adsec.database.repositories.clients import ClientRepository
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.findings import FindingRepository
from adsec.database.repositories.graph import AttackPathRepository
from adsec.database.repositories.scopes import ScopeRepository
from adsec.export.csv_export import export_findings_csv
from adsec.export.json_export import export_findings_json
from adsec.reporting.data import build_report_data
from adsec.reporting.html import render_executive_html, render_technical_html
from adsec.reporting.limitations import compute_limitations
from adsec.reporting.markdown import render_executive_markdown, render_technical_markdown

app = typer.Typer(help="Generation de rapports (executif/technique, plusieurs formats).")


@app.command("generate")
def generate_report(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    kind: str = typer.Option("technical", "--kind", help="executive|technical"),
    output_format: str = typer.Option("markdown", "--format", help="markdown|html|json|csv"),
    sanitize: bool = typer.Option(False, "--sanitize", help="Masquer IP/emails/secrets"),
    output: Path = typer.Option(None, "--output", help="Chemin de sortie"),  # noqa: B008
) -> None:
    """Genere un rapport executif ou technique, dans le format demande."""
    if kind not in ("executive", "technical"):
        print_error("--kind doit etre 'executive' ou 'technical'.")
        raise typer.Exit(code=1)
    if output_format not in ("markdown", "html", "json", "csv"):
        print_error("--format doit etre 'markdown', 'html', 'json' ou 'csv'.")
        raise typer.Exit(code=1)

    ctx = get_context()
    conn = ctx.database.connection
    try:
        eng = EngagementRepository(conn).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    client = ClientRepository(conn).get_by_id(eng.client_id)
    client_name = client.name if client else eng.client_id

    findings = FindingRepository(conn).list(eng.id)
    if not findings and output_format in ("json", "csv"):
        print_error("Aucun finding : lancez 'adsec scan run' d'abord.")
        raise typer.Exit(code=1)

    out_dir = ctx.settings.reports_dir / eng.id
    out_dir.mkdir(parents=True, exist_ok=True)

    if output_format == "json":
        path = output or (out_dir / "findings.json")
        export_findings_json(findings, path)
    elif output_format == "csv":
        path = output or (out_dir / "findings.csv")
        export_findings_csv(findings, path)
    else:
        scope_entries = ScopeRepository(conn).list_for_engagement(eng.id)
        scope_summary = [f"{e.entry_type.value}: {e.value}" for e in scope_entries] or [
            "Scope non renseigne."
        ]
        attack_paths = AttackPathRepository(conn).list_all(eng.id)
        limitations = compute_limitations(conn, eng.id)

        data = build_report_data(
            kind=kind,
            engagement=eng,
            client_name=client_name,
            scope_summary=scope_summary,
            limitations=limitations,
            findings=findings,
            attack_paths=attack_paths,
            sanitize=sanitize,
        )
        if output_format == "markdown":
            content = (
                render_executive_markdown(data)
                if kind == "executive"
                else render_technical_markdown(data)
            )
            default_name = f"report-{kind}.md"
        else:
            content = (
                render_executive_html(data) if kind == "executive" else render_technical_html(data)
            )
            default_name = f"report-{kind}.html"
        path = output or (out_dir / default_name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    print_success(f"Rapport ecrit : {path}")
