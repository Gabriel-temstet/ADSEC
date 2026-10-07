"""Contexte d'execution partage par toutes les commandes CLI : chargement
de la configuration et ouverture de la base de donnees (avec migrations
appliquees automatiquement)."""

from __future__ import annotations

from dataclasses import dataclass

from adsec.config.settings import AppSettings, load_settings
from adsec.database.connection import Database


@dataclass
class CliContext:
    settings: AppSettings
    database: Database


_context: CliContext | None = None


def get_context() -> CliContext:
    global _context
    if _context is None:
        settings = load_settings()
        settings.ensure_directories()
        database = Database(settings.database_path)
        _context = CliContext(settings=settings, database=database)
    return _context


def reset_context() -> None:
    """Reinitialise le contexte (utilise par les tests)."""
    global _context
    if _context is not None:
        _context.database.close()
    _context = None
