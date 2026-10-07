"""Pipeline de scan : Discovery -> Collection -> Normalization ->
Persistence -> Controles (plugins).

Phase 3 : seul le collector LDAP est branche. Les findings produits par
les plugins sont comptes et retournes dans le resume ; leur persistance
(table `findings`, evidence, deduplication) arrive avec les phases
suivantes.
"""

from __future__ import annotations

import hashlib
import sqlite3
from dataclasses import dataclass, field
from datetime import UTC, datetime

from adsec import __version__
from adsec.collectors.base import CollectionResult, DiscoveryResult
from adsec.collectors.dns.collector import DnsCollector, ProbeFactory
from adsec.collectors.ldap.collector import LdapCollector
from adsec.collectors.ldap.connection import ConnectionFactory
from adsec.collectors.ldap.normalizer import NormalizedDirectory, normalize_ldap_collection
from adsec.collectors.smb.collector import SessionFactory, SmbCollector
from adsec.config.settings import ProfileDefinition
from adsec.core.events.audit_log import AuditLog
from adsec.core.models.ad_objects import Domain, DomainController, Forest
from adsec.core.models.engagement import Engagement
from adsec.core.models.enums import AccessLevel, ScanJobStatus, ScanProfile
from adsec.core.models.network import DnsZoneCheck, SmbHost, SmbShare
from adsec.core.models.scan import ScanJob
from adsec.core.scheduler.scheduler import (
    Scheduler,
    SchedulerSafetyConfig,
    Task,
    TaskPriority,
    TaskResult,
    TaskStatus,
)
from adsec.core.scope.scope_manager import ScopeManager
from adsec.credentials.provider import CredentialProvider
from adsec.database.repositories.acl import AclRepository, TrustRepository
from adsec.database.repositories.directory import DirectoryRepository, GpoRepository
from adsec.database.repositories.findings import FindingRepository
from adsec.database.repositories.graph import AttackPathRepository
from adsec.database.repositories.network import DnsRepository, SmbRepository
from adsec.database.repositories.scan_jobs import ScanJobRepository
from adsec.database.repositories.topology import TopologyRepository
from adsec.graph.builder import build_graph, build_sid_to_dn, critical_targets
from adsec.graph.correlation import correlate
from adsec.graph.path_finder import find_attack_paths
from adsec.rules.base import Finding, NormalizedData, ScanContext
from adsec.rules.registry import PluginManager


@dataclass
class ScanSummary:
    scan_job_id: str
    status: ScanJobStatus
    access_level: AccessLevel
    domain_fqdn: str | None = None
    counts: dict[str, int] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    plugins_run: list[str] = field(default_factory=list)
    new_findings: int = 0
    updated_findings: int = 0


def _now_iso() -> str:
    return datetime.now(UTC).isoformat()


class ScanPipeline:
    def __init__(
        self,
        conn: sqlite3.Connection,
        engagement: Engagement,
        scope_manager: ScopeManager,
        credential_provider: CredentialProvider,
        profile: ScanProfile,
        profile_definition: ProfileDefinition,
        audit_log: AuditLog,
        safety_config: SchedulerSafetyConfig,
        plugin_manager: PluginManager | None = None,
        port: int = 389,
        use_ssl: bool = False,
        connection_factory: ConnectionFactory | None = None,
        smb_port: int = 445,
        smb_session_factory: SessionFactory | None = None,
        dns_port: int = 53,
        dns_probe_factory: ProbeFactory | None = None,
    ) -> None:
        self._conn = conn
        self._engagement = engagement
        self._scope = scope_manager
        self._profile = profile
        self._profile_def = profile_definition
        self._audit = audit_log
        self._plugins = plugin_manager or PluginManager().discover()
        self._scheduler = Scheduler(
            SchedulerSafetyConfig(
                **{
                    **safety_config.__dict__,
                    "max_workers": min(safety_config.max_workers, profile_definition.max_workers),
                    "max_requests_per_second": min(
                        safety_config.max_requests_per_second,
                        profile_definition.max_requests_per_second,
                    ),
                }
            )
        )
        self._collector = LdapCollector(
            scope_manager,
            credential_provider,
            port=port,
            use_ssl=use_ssl,
            connection_factory=connection_factory,
        )
        self._smb_collector = SmbCollector(
            scope_manager, credential_provider, port=smb_port, session_factory=smb_session_factory
        )
        self._dns_collector = DnsCollector(
            scope_manager, port=dns_port, probe_factory=dns_probe_factory
        )
        self._topology = TopologyRepository(conn)
        self._directory = DirectoryRepository(conn)
        self._acls = AclRepository(conn)
        self._gpos = GpoRepository(conn)
        self._trusts = TrustRepository(conn)
        self._smb = SmbRepository(conn)
        self._dns = DnsRepository(conn)
        self._findings = FindingRepository(conn)
        self._attack_paths = AttackPathRepository(conn)
        self._jobs = ScanJobRepository(conn)

    @property
    def scheduler(self) -> Scheduler:
        return self._scheduler

    def _configuration_hash(self, target: str) -> str:
        scope_json = self._scope.scope.model_dump_json()
        raw = f"{self._profile.value}|{target}|{scope_json}"
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()

    def _audit_record(self, target: str, operation: str, result: str) -> None:
        self._audit.record(
            engagement_id=self._engagement.id,
            operator=self._engagement.operator or "unknown",
            target=target,
            operation=operation,
            plugin=self._collector.id,
            result=result,
        )

    async def run(self, target: str) -> ScanSummary:
        plugin_versions = {p.id: p.version for p in self._plugins.all_plugins()}
        job = self._jobs.create(
            ScanJob(
                engagement_id=self._engagement.id,
                profile=self._profile,
                status=ScanJobStatus.RUNNING,
                tool_version=__version__,
                plugin_versions=plugin_versions,
                configuration_hash=self._configuration_hash(target),
                started_at=datetime.now(UTC),
                operator=self._engagement.operator,
            )
        )
        summary = ScanSummary(
            scan_job_id=job.id, status=ScanJobStatus.RUNNING, access_level=AccessLevel.ANONYMOUS
        )

        try:
            discovery = await self._run_discovery(target, summary)
            if discovery is None:
                return self._finish(job, summary, ScanJobStatus.FAILED)

            summary.access_level = discovery.access_level_achieved
            summary.limitations.extend(discovery.limitations)
            domain = self._persist_topology(discovery)
            summary.domain_fqdn = domain.fqdn

            if "collection" not in self._profile_def.allowed_categories:
                summary.limitations.append(
                    f"Profil {self._profile.value}: collecte desactivee (decouverte uniquement)"
                )
                return self._finish(job, summary, ScanJobStatus.COMPLETED)

            collection = await self._run_collection(target, summary)
            if collection is None:
                return self._finish(job, summary, ScanJobStatus.FAILED)

            summary.limitations.extend(collection.limitations)
            summary.errors.extend(collection.errors)
            normalized = normalize_ldap_collection(self._engagement.id, domain.id, collection)
            self._persist_directory(normalized)
            summary.counts = {
                "ous": len(normalized.ous),
                "users": len(normalized.users),
                "groups": len(normalized.groups),
                "computers": len(normalized.computers),
                "memberships": len(normalized.memberships),
                "acls": len(normalized.acls),
                "trusts": len(normalized.trusts),
                "gpos": len(normalized.gpos),
            }

            extra_tables: dict[str, list[dict[str, object]]] = {}
            if "smb" in self._profile_def.allowed_categories:
                smb_host = await self._run_smb(target, summary)
                if smb_host is not None:
                    self._smb.upsert_host(smb_host)
                    extra_tables["smb_hosts"] = [smb_host.model_dump()]
                    summary.counts["smb_shares"] = len(smb_host.shares)

            if "dns" in self._profile_def.allowed_categories:
                zone_check = await self._run_dns(target, domain.fqdn, summary)
                if zone_check is not None:
                    self._dns.upsert_zone_check(zone_check)
                    extra_tables["dns_zone_checks"] = [zone_check.model_dump()]

            persisted_findings = await self._run_plugins(job, summary, normalized, extra_tables)

            if "attackpaths" in self._profile_def.allowed_categories:
                summary.counts["attack_paths"] = self._build_and_persist_graph(
                    job, normalized, domain.fqdn, persisted_findings
                )

            status = (
                ScanJobStatus.CANCELLED
                if self._scheduler.is_stopping()
                else ScanJobStatus.COMPLETED
            )
            return self._finish(job, summary, status)
        except Exception as exc:  # noqa: BLE001 - un scan ne doit jamais perdre son etat
            summary.errors.append(f"{type(exc).__name__}: {exc}")
            self._audit_record(target, "scan", f"erreur: {type(exc).__name__}")
            return self._finish(job, summary, ScanJobStatus.FAILED)

    # -- etapes ----------------------------------------------------------

    async def _run_discovery(self, target: str, summary: ScanSummary) -> DiscoveryResult | None:
        task = Task(
            name=f"ldap-discovery:{target}",
            coro_factory=lambda: self._collector.discover(target),
            target_key=target,
            priority=TaskPriority.DISCOVERY,
            scope_check=lambda: self._scope.is_in_scope(target),
            max_retries=1,
        )
        result = await self._run_single(task)
        self._audit_record(target, "ldap-discovery", result.status.name)
        if result.status != TaskStatus.SUCCEEDED or not isinstance(result.result, DiscoveryResult):
            summary.errors.append(_describe_failure("Decouverte LDAP", result))
            return None
        return result.result

    async def _run_collection(self, target: str, summary: ScanSummary) -> CollectionResult | None:
        task = Task(
            name=f"ldap-collection:{target}",
            coro_factory=lambda: self._collector.collect(target),
            target_key=target,
            priority=TaskPriority.COLLECTION,
            timeout_seconds=300.0,
            scope_check=lambda: self._scope.is_in_scope(target),
            max_retries=1,
        )
        result = await self._run_single(task)
        self._audit_record(target, "ldap-collection", result.status.name)
        if result.status != TaskStatus.SUCCEEDED or not isinstance(result.result, CollectionResult):
            summary.errors.append(_describe_failure("Collecte LDAP", result))
            return None
        return result.result

    async def _run_smb(self, target: str, summary: ScanSummary) -> SmbHost | None:
        disco_task = Task(
            name=f"smb-discovery:{target}",
            coro_factory=lambda: self._smb_collector.discover(target),
            target_key=target,
            priority=TaskPriority.DISCOVERY,
            scope_check=lambda: self._scope.is_in_scope(target),
            max_retries=1,
        )
        disco_result = await self._run_single(disco_task)
        self._audit_record(target, "smb-discovery", disco_result.status.name)
        if disco_result.status != TaskStatus.SUCCEEDED or not isinstance(
            disco_result.result, DiscoveryResult
        ):
            summary.limitations.append(_describe_failure("Decouverte SMB", disco_result))
            return None
        discovery = disco_result.result
        if discovery.partial:
            summary.limitations.extend(f"SMB: {lim}" for lim in discovery.limitations)
            return None

        collect_task = Task(
            name=f"smb-collection:{target}",
            coro_factory=lambda: self._smb_collector.collect(target),
            target_key=target,
            priority=TaskPriority.COLLECTION,
            timeout_seconds=60.0,
            scope_check=lambda: self._scope.is_in_scope(target),
            max_retries=1,
        )
        collect_result = await self._run_single(collect_task)
        self._audit_record(target, "smb-collection", collect_result.status.name)
        if collect_result.status != TaskStatus.SUCCEEDED or not isinstance(
            collect_result.result, CollectionResult
        ):
            summary.limitations.append(_describe_failure("Collecte SMB", collect_result))
            return None
        collection = collect_result.result
        summary.errors.extend(f"SMB: {err}" for err in collection.errors)

        raw_shares = collection.objects.get("shares", [])
        return SmbHost(
            engagement_id=self._engagement.id,
            hostname=target,
            dialect=str(discovery.facts.get("dialect")),
            is_smb1=bool(discovery.facts.get("is_smb1")),
            signing_required=bool(discovery.facts.get("signing_required")),
            guest_or_anonymous=bool(discovery.facts.get("guest_or_anonymous")),
            shares=[SmbShare.model_validate(row) for row in raw_shares],
        )

    async def _run_dns(self, target: str, zone: str, summary: ScanSummary) -> DnsZoneCheck | None:
        disco_task = Task(
            name=f"dns-discovery:{target}",
            coro_factory=lambda: self._dns_collector.discover(target),
            target_key=target,
            priority=TaskPriority.DISCOVERY,
            scope_check=lambda: self._scope.is_in_scope(target),
            max_retries=1,
        )
        disco_result = await self._run_single(disco_task)
        self._audit_record(target, "dns-discovery", disco_result.status.name)
        if disco_result.status != TaskStatus.SUCCEEDED or not isinstance(
            disco_result.result, DiscoveryResult
        ):
            summary.limitations.append(_describe_failure("Decouverte DNS", disco_result))
            return None
        if disco_result.result.partial:
            summary.limitations.extend(f"DNS: {lim}" for lim in disco_result.result.limitations)
            return None

        collect_task = Task(
            name=f"dns-collection:{target}",
            coro_factory=lambda: self._dns_collector.collect(target, zone),
            target_key=target,
            priority=TaskPriority.COLLECTION,
            timeout_seconds=30.0,
            scope_check=lambda: self._scope.is_in_scope(target),
            max_retries=1,
        )
        collect_result = await self._run_single(collect_task)
        self._audit_record(target, "dns-collection", collect_result.status.name)
        if collect_result.status != TaskStatus.SUCCEEDED or not isinstance(
            collect_result.result, CollectionResult
        ):
            summary.limitations.append(_describe_failure("Collecte DNS", collect_result))
            return None
        collection = collect_result.result
        summary.limitations.extend(f"DNS: {lim}" for lim in collection.limitations)
        rows = collection.objects.get("dns_zone_checks", [])
        if not rows:
            return None
        return DnsZoneCheck.model_validate({**rows[0], "engagement_id": self._engagement.id})

    async def _run_single(self, task: Task) -> TaskResult:
        results = await self._scheduler.run([task])
        for res in results:
            if res.task.id == task.id:
                return res
        return TaskResult(task=task, status=TaskStatus.CANCELLED, error="tache non executee")

    def _persist_topology(self, discovery: DiscoveryResult) -> Domain:
        facts = discovery.facts
        fqdn = str(facts["domain_fqdn"])
        forest = self._topology.upsert_forest(
            Forest(
                engagement_id=self._engagement.id,
                name=fqdn,
                functional_level=_str_or_none(facts.get("forest_functionality")),
            )
        )
        domain = self._topology.upsert_domain(
            Domain(
                engagement_id=self._engagement.id,
                forest_id=forest.id,
                fqdn=fqdn,
                functional_level=_str_or_none(facts.get("domain_functionality")),
                naming_context=str(facts["naming_context"]),
            )
        )
        dns_hostname = _str_or_none(facts.get("dns_hostname"))
        if dns_hostname:
            self._topology.upsert_domain_controller(
                DomainController(
                    engagement_id=self._engagement.id,
                    domain_id=domain.id,
                    hostname=dns_hostname,
                )
            )
        return domain

    def _persist_directory(self, normalized: NormalizedDirectory) -> None:
        for ou in normalized.ous:
            self._directory.upsert_ou(ou)
        for user in normalized.users:
            self._directory.upsert_user(user)
        for group in normalized.groups:
            self._directory.upsert_group(group)
        for computer in normalized.computers:
            self._directory.upsert_computer(computer)
        for membership in normalized.memberships:
            self._directory.upsert_membership(membership)
        for acl in normalized.acls:
            self._acls.upsert_acl(acl)
        for trust in normalized.trusts:
            self._trusts.upsert_trust(trust)
        for gpo in normalized.gpos:
            self._gpos.upsert_gpo(gpo)

    async def _run_plugins(
        self,
        job: ScanJob,
        summary: ScanSummary,
        normalized: NormalizedDirectory,
        extra_tables: dict[str, list[dict[str, object]]] | None = None,
    ) -> list[tuple[str, Finding]]:
        selected = self._plugins.select_plugins(
            access_level=summary.access_level,
            profile=self._profile,
            allowed_categories=self._profile_def.allowed_categories,
            allow_intrusive=False,
        )
        all_eligible = self._plugins.select_plugins(
            access_level=AccessLevel.PRIVILEGED,
            profile=self._profile,
            allowed_categories=self._profile_def.allowed_categories,
            allow_intrusive=False,
        )
        selected_ids = {p.id for p in selected}
        skipped = sorted(p.id for p in all_eligible if p.id not in selected_ids)
        if skipped:
            summary.limitations.append(
                f"{len(skipped)} controle(s) ignore(s) faute de niveau d'acces suffisant "
                f"(niveau atteint : {summary.access_level.value}) : {', '.join(skipped)}"
            )
        data = NormalizedData(
            engagement_id=self._engagement.id,
            tables={
                "engagement_config": [
                    {
                        "intrusive_actions_enabled": self._scope.intrusive_allowed(),
                    }
                ],
                "users": [u.model_dump() for u in normalized.users],
                "groups": [g.model_dump() for g in normalized.groups],
                "computers": [c.model_dump() for c in normalized.computers],
                "ous": [o.model_dump() for o in normalized.ous],
                "acls": [a.model_dump() for a in normalized.acls],
                "trusts": [t.model_dump() for t in normalized.trusts],
                "gpos": [g.model_dump() for g in normalized.gpos],
                **(extra_tables or {}),
            },
        )
        ctx = ScanContext(
            engagement_id=self._engagement.id,
            scan_job_id=job.id,
            access_level=summary.access_level,
            profile=self._profile.value,
        )
        persisted: list[tuple[str, Finding]] = []
        for plugin_cls in selected:
            plugin = plugin_cls()
            try:
                findings = await plugin.run(ctx, data)
            except Exception as exc:  # noqa: BLE001 - un plugin defaillant n'arrete pas le scan
                summary.errors.append(f"Plugin {plugin.id}: {type(exc).__name__}: {exc}")
                continue
            summary.plugins_run.append(plugin.id)
            for finding in findings:
                stored, created = self._findings.upsert(
                    self._engagement.id, job.id, finding, collector_version=__version__
                )
                summary.findings.append(finding)
                persisted.append((stored.id, finding))
                if created:
                    summary.new_findings += 1
                else:
                    summary.updated_findings += 1
        return persisted

    def _build_and_persist_graph(
        self,
        job: ScanJob,
        normalized: NormalizedDirectory,
        domain_fqdn: str,
        persisted_findings: list[tuple[str, Finding]],
    ) -> int:
        """Construit le graphe et calcule les chemins vers les actifs
        critiques (groupes integres a privileges, controleurs de domaine,
        le domaine lui-meme pour la portee DCSync). Remplace l'ensemble des
        chemins precedents de l'engagement : ils sont deterministes a
        partir des donnees courantes, pas d'historique a preserver ici."""
        users = [u.model_dump() for u in normalized.users]
        groups = [g.model_dump() for g in normalized.groups]
        computers = [c.model_dump() for c in normalized.computers]

        graph = build_graph(
            users=users,
            groups=groups,
            computers=computers,
            memberships=[m.model_dump() for m in normalized.memberships],
            acls=[a.model_dump() for a in normalized.acls],
            gpos=[g.model_dump() for g in normalized.gpos],
            domain_fqdn=domain_fqdn,
        )
        targets = critical_targets(groups, computers, domain_fqdn)
        paths = find_attack_paths(graph, self._engagement.id, targets)
        path_ids = self._attack_paths.replace_all(self._engagement.id, job.id, paths)

        sid_to_dn = build_sid_to_dn(users, groups, computers)
        correlations = correlate(persisted_findings, paths, sid_to_dn)
        links = [
            (c.finding_id, path_ids[c.path_index])
            for c in correlations
            if c.path_index < len(path_ids)
        ]
        self._attack_paths.link_findings(self._engagement.id, links)

        return len(paths)

    def _finish(self, job: ScanJob, summary: ScanSummary, status: ScanJobStatus) -> ScanSummary:
        summary.status = status
        self._jobs.update_status(job.id, status, ended_at=_now_iso())
        return summary


def _str_or_none(value: object) -> str | None:
    return None if value is None else str(value)


def _describe_failure(label: str, result: TaskResult) -> str:
    detail = result.error or result.status.name
    return f"{label}: {result.status.name} ({detail})"
