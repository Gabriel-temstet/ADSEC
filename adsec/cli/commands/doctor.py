"""Commande `adsec doctor` : verifie l'environnement d'execution."""

from __future__ import annotations

import sys

import typer

from adsec.cli.formatting import print_table
from adsec.config.settings import (
    load_default_safety_config,
    load_profile_definitions,
    load_settings,
)
from adsec.database.connection import Database, current_schema_version
from adsec.rules.registry import PluginManager

app = typer.Typer(help="Diagnostic de l'environnement.")


@app.command("run")
def run_doctor() -> None:
    """Verifie dependances, configuration, base de donnees et plugins."""
    checks: list[list[str]] = []

    # Python
    py_ok = sys.version_info >= (3, 11)
    checks.append(
        ["Version Python", f"{sys.version_info.major}.{sys.version_info.minor}", _status(py_ok)]
    )

    # Configuration
    try:
        settings = load_settings()
        settings.ensure_directories()
        checks.append(["Configuration", f"data_dir={settings.data_dir}", _status(True)])
    except Exception as exc:  # noqa: BLE001
        checks.append(["Configuration", str(exc), _status(False)])
        _print_and_exit(checks)
        return

    # Profils de scan
    try:
        profiles = load_profile_definitions()
        checks.append(["Profils de scan", ", ".join(sorted(profiles)), _status(bool(profiles))])
    except Exception as exc:  # noqa: BLE001
        checks.append(["Profils de scan", str(exc), _status(False)])

    # Parametres de securite
    try:
        safety = load_default_safety_config()
        checks.append(
            [
                "Parametres de securite",
                f"max_workers={safety.max_workers}, max_rps={safety.max_requests_per_second}",
                _status(True),
            ]
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(["Parametres de securite", str(exc), _status(False)])

    # Base de donnees + migrations
    try:
        db = Database(settings.database_path)
        version = current_schema_version(db.connection)
        checks.append(
            ["Base SQLite", f"{settings.database_path} (schema v{version})", _status(True)]
        )
        db.close()
    except Exception as exc:  # noqa: BLE001
        checks.append(["Base SQLite", str(exc), _status(False)])

    # Plugin manager
    try:
        manager = PluginManager().discover()
        plugin_count = len(manager.all_plugins())
        error_count = len(manager.load_errors)
        status_ok = plugin_count > 0 and error_count == 0
        checks.append(
            [
                "Plugins",
                f"{plugin_count} plugin(s) charge(s), {error_count} erreur(s)",
                _status(status_ok),
            ]
        )
    except Exception as exc:  # noqa: BLE001
        checks.append(["Plugins", str(exc), _status(False)])

    _print_and_exit(checks)


def _status(ok: bool) -> str:
    return "[bold green]OK[/bold green]" if ok else "[bold red]ECHEC[/bold red]"


def _print_and_exit(checks: list[list[str]]) -> None:
    print_table("adsec doctor", ["Verification", "Detail", "Statut"], checks)
    if any("ECHEC" in row[2] for row in checks):
        raise typer.Exit(code=1)
