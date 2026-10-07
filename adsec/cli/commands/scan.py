"""Commandes `adsec scan` et `adsec inventory`."""

from __future__ import annotations

import asyncio

import typer

from adsec.cli.context import get_context
from adsec.cli.formatting import console, print_error, print_success, print_table
from adsec.collectors.dns.collector import ProbeFactory
from adsec.collectors.ldap.connection import ConnectionFactory
from adsec.collectors.smb.collector import SessionFactory
from adsec.config.settings import (
    default_intrusive_actions_enabled,
    load_default_safety_config,
    load_profile_definitions,
)
from adsec.core.engine.pipeline import ScanPipeline, ScanSummary
from adsec.core.events.audit_log import AuditLog
from adsec.core.models.enums import EngagementStatus, ScanProfile
from adsec.core.scope.scope_manager import ScopeManager
from adsec.credentials.provider import EnvironmentCredentialProvider
from adsec.database.repositories.acl import AclRepository, TrustRepository
from adsec.database.repositories.directory import DirectoryRepository, GpoRepository
from adsec.database.repositories.engagements import EngagementNotFoundError, EngagementRepository
from adsec.database.repositories.graph import AttackPathRepository
from adsec.database.repositories.network import DnsRepository, SmbRepository
from adsec.database.repositories.scopes import ScopeRepository
from adsec.database.repositories.topology import TopologyRepository

app = typer.Typer(help="Lancement de scans et consultation de l'inventaire.")

# Fabrique de connexion injectable (utilisee par les tests pour remplacer
# la connexion LDAP reelle par une connexion simulee).
_connection_factory_override: ConnectionFactory | None = None
_smb_session_factory_override: SessionFactory | None = None
_dns_probe_factory_override: ProbeFactory | None = None


def set_connection_factory(factory: ConnectionFactory | None) -> None:
    global _connection_factory_override
    _connection_factory_override = factory


def set_smb_session_factory(factory: SessionFactory | None) -> None:
    global _smb_session_factory_override
    _smb_session_factory_override = factory


def set_dns_probe_factory(factory: ProbeFactory | None) -> None:
    global _dns_probe_factory_override
    _dns_probe_factory_override = factory


@app.command("run")
def run_scan(
    engagement: str = typer.Argument(..., help="ID ou nom de l'engagement"),
    target: str = typer.Argument(..., help="Controleur de domaine cible (FQDN ou IP)"),
    profile: ScanProfile = typer.Option(None, "--profile", help="passive|safe|standard|deep"),  # noqa: B008
    port: int = typer.Option(389, "--port", help="Port LDAP"),
    ssl: bool = typer.Option(False, "--ssl", help="Utiliser LDAPS"),
) -> None:
    """Lance un scan (decouverte + collecte LDAP + controles) sur une cible en scope.

    Authentification : variables ADSEC_LDAP_BIND_DN / ADSEC_LDAP_BIND_PASSWORD
    (bind anonyme si absentes)."""
    ctx = get_context()
    conn = ctx.database.connection
    engagement_repo = EngagementRepository(conn)
    scope_repo = ScopeRepository(conn)

    try:
        eng = engagement_repo.resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    scope = scope_repo.build_scope(eng.id, default_intrusive_actions_enabled())
    if scope.is_empty():
        print_error("Scope vide : definissez-le avec 'adsec scope add' avant tout scan.")
        raise typer.Exit(code=1)

    scope_manager = ScopeManager(scope)
    decision = scope_manager.evaluate(target)
    if not decision.in_scope:
        print_error(f"Cible hors scope refusee: {target!r} ({decision.reason})")
        raise typer.Exit(code=1)

    effective_profile = profile or eng.default_profile
    profiles = load_profile_definitions()
    profile_def = profiles[effective_profile.value]

    engagement_repo.update_status(eng.id, EngagementStatus.ACTIVE)
    audit = AuditLog(ctx.settings.audit_log_dir / f"{eng.id}.jsonl")

    pipeline = ScanPipeline(
        conn=conn,
        engagement=eng,
        scope_manager=scope_manager,
        credential_provider=EnvironmentCredentialProvider(),
        profile=effective_profile,
        profile_definition=profile_def,
        audit_log=audit,
        safety_config=load_default_safety_config(),
        port=port,
        use_ssl=ssl,
        connection_factory=_connection_factory_override,
        smb_session_factory=_smb_session_factory_override,
        dns_probe_factory=_dns_probe_factory_override,
    )

    console.print(f"Scan {effective_profile.value} de {target} (engagement {eng.name})...")
    summary = asyncio.run(pipeline.run(target))
    _print_summary(summary)
    if summary.status.value == "failed":
        raise typer.Exit(code=1)


def _print_summary(summary: ScanSummary) -> None:
    rows = [
        ["scan_job", summary.scan_job_id],
        ["statut", summary.status.value],
        ["niveau d'acces", summary.access_level.value],
        ["domaine", summary.domain_fqdn or "-"],
    ]
    for kind, count in summary.counts.items():
        rows.append([kind, str(count)])
    rows.append(["plugins executes", ", ".join(summary.plugins_run) or "-"])
    rows.append(
        [
            "findings",
            (
                f"{len(summary.findings)} ({summary.new_findings} nouveaux, "
                f"{summary.updated_findings} deja connus)"
            ),
        ]
    )
    print_table("Resume du scan", ["Champ", "Valeur"], rows)

    for finding in summary.findings:
        console.print(f"  [{finding.severity.value.upper()}] {finding.rule_id} - {finding.title}")
    for limitation in summary.limitations:
        console.print(f"  Limitation: {limitation}")
    for error in summary.errors:
        print_error(error)
    if summary.status.value == "completed":
        print_success("Scan termine.")


@app.command("inventory")
def inventory(engagement: str = typer.Argument(..., help="ID ou nom de l'engagement")) -> None:
    """Affiche l'inventaire AD collecte pour un engagement."""
    ctx = get_context()
    conn = ctx.database.connection
    try:
        eng = EngagementRepository(conn).resolve(engagement)
    except EngagementNotFoundError as exc:
        print_error(str(exc))
        raise typer.Exit(code=1) from exc

    topology = TopologyRepository(conn)
    directory = DirectoryRepository(conn)
    domains = topology.list_domains(eng.id)
    if not domains:
        print_error("Aucune donnee collectee : lancez 'adsec scan run' d'abord.")
        raise typer.Exit(code=1)

    print_table(
        f"Inventaire - {eng.name}",
        ["Objet", "Nombre"],
        [
            ["domaines", str(len(domains))],
            ["controleurs de domaine", str(len(topology.list_domain_controllers(eng.id)))],
            ["OUs", str(len(directory.list_ous(eng.id)))],
            ["utilisateurs", str(len(directory.list_users(eng.id)))],
            ["groupes", str(len(directory.list_groups(eng.id)))],
            ["ordinateurs", str(len(directory.list_computers(eng.id)))],
            ["appartenances", str(len(directory.list_all_memberships(eng.id)))],
            ["ACL analysees", str(len(AclRepository(conn).list_acls(eng.id)))],
            ["trusts", str(len(TrustRepository(conn).list_trusts(eng.id)))],
            ["GPO", str(len(GpoRepository(conn).list_gpos(eng.id)))],
            ["hotes SMB", str(len(SmbRepository(conn).list_hosts(eng.id)))],
            ["zones DNS", str(len(DnsRepository(conn).list_zone_checks(eng.id)))],
            ["chemins d'attaque", str(len(AttackPathRepository(conn).list_all(eng.id)))],
        ],
    )
