"""Helpers de rendu console partages par les commandes CLI."""

from __future__ import annotations

from rich.console import Console
from rich.table import Table

console = Console()
error_console = Console(stderr=True, style="bold red")


def print_table(title: str, columns: list[str], rows: list[list[str]]) -> None:
    table = Table(title=title, show_lines=False)
    for col in columns:
        table.add_column(col)
    for row in rows:
        table.add_row(*row)
    console.print(table)


def print_error(message: str) -> None:
    error_console.print(f"[ERREUR] {message}")


def print_success(message: str) -> None:
    console.print(f"[bold green]OK[/bold green] {message}")
