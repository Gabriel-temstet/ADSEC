from __future__ import annotations

from typing import ClassVar

import pytest

from adsec.core.models.enums import AccessLevel, Confidence, ScanProfile, Severity
from adsec.rules.base import CheckPlugin, DataRequirement, Finding, NormalizedData, ScanContext
from adsec.rules.registry import DuplicatePluginIdError, PluginManager


class _DummyPlugin(CheckPlugin):
    id = "AD-TEST-001"
    name = "Dummy"
    version = "1.0.0"
    category = "test"
    description = "Plugin de test"
    severity_hint = Severity.LOW
    required_permissions = AccessLevel.AUTHENTICATED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = False

    def requires(self) -> list[DataRequirement]:
        return [DataRequirement(kind="users")]

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        return []


class _IntrusivePlugin(CheckPlugin):
    id = "AD-TEST-002"
    name = "Intrusive dummy"
    version = "1.0.0"
    category = "test"
    description = "Plugin intrusif de test"
    severity_hint = Severity.CRITICAL
    required_permissions = AccessLevel.PRIVILEGED
    protocols: ClassVar[list[str]] = ["ldap"]
    intrusive = True

    def requires(self) -> list[DataRequirement]:
        return []

    async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
        return []


def test_missing_required_attribute_raises_type_error() -> None:
    with pytest.raises(TypeError):

        class _Broken(CheckPlugin):
            id = "AD-TEST-999"
            # attributs obligatoires manquants volontairement

            def requires(self) -> list[DataRequirement]:
                return []

            async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
                return []


def test_register_and_get_plugin() -> None:
    manager = PluginManager()
    manager.register(_DummyPlugin)
    assert manager.get("AD-TEST-001") is _DummyPlugin
    assert len(manager.all_plugins()) == 1


def test_duplicate_plugin_id_raises() -> None:
    class _Other(CheckPlugin):
        id = "AD-TEST-001"
        name = "Other"
        version = "1.0.0"
        category = "test"
        description = "Autre plugin avec le meme id"
        severity_hint = Severity.LOW
        required_permissions = AccessLevel.AUTHENTICATED
        protocols: ClassVar[list[str]] = ["ldap"]

        def requires(self) -> list[DataRequirement]:
            return []

        async def run(self, ctx: ScanContext, data: NormalizedData) -> list[Finding]:
            return []

    manager = PluginManager()
    manager.register(_DummyPlugin)
    with pytest.raises(DuplicatePluginIdError):
        manager.register(_Other)


def test_intrusive_plugin_excluded_by_default() -> None:
    manager = PluginManager()
    manager.register(_DummyPlugin)
    manager.register(_IntrusivePlugin)

    selected = manager.select_plugins(access_level=AccessLevel.PRIVILEGED, profile=ScanProfile.DEEP)
    ids = {p.id for p in selected}
    assert "AD-TEST-001" in ids
    assert "AD-TEST-002" not in ids


def test_intrusive_plugin_included_when_explicitly_allowed() -> None:
    manager = PluginManager()
    manager.register(_IntrusivePlugin)

    selected = manager.select_plugins(
        access_level=AccessLevel.PRIVILEGED,
        profile=ScanProfile.DEEP,
        allow_intrusive=True,
    )
    assert any(p.id == "AD-TEST-002" for p in selected)


def test_plugin_excluded_when_access_level_insufficient() -> None:
    manager = PluginManager()
    manager.register(_DummyPlugin)  # requiert AUTHENTICATED

    selected = manager.select_plugins(access_level=AccessLevel.ANONYMOUS, profile=ScanProfile.SAFE)
    assert selected == []


def test_discover_finds_internal_builtin_plugin() -> None:
    manager = PluginManager().discover()
    assert manager.get("AD-SEC-000") is not None
    assert manager.load_errors == []


def test_finding_fingerprint_is_stable_and_order_independent() -> None:
    f1 = Finding(
        rule_id="AD-ACL-001",
        title="t",
        category="acl",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="d",
        technical_details="td",
        impact="i",
        validation_procedure="v",
        remediation="r",
        affected_assets=["obj2", "obj1"],
    )
    f2 = Finding(
        rule_id="AD-ACL-001",
        title="autre titre",
        category="acl",
        severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        description="autre",
        technical_details="autre",
        impact="autre",
        validation_procedure="autre",
        remediation="autre",
        affected_assets=["obj1", "obj2"],
    )
    assert f1.fingerprint("alice") == f2.fingerprint("alice")


@pytest.mark.asyncio
async def test_safe_posture_plugin_flags_intrusive_enabled() -> None:
    from adsec.rules.security.ad_sec_000_safe_posture import SafePostureCheck

    plugin = SafePostureCheck()
    ctx = ScanContext(
        engagement_id="ENG-1", scan_job_id="JOB-1", access_level=AccessLevel.AUDITOR, profile="safe"
    )
    data = NormalizedData(
        engagement_id="ENG-1",
        tables={"engagement_config": [{"intrusive_actions_enabled": True}]},
    )
    findings = await plugin.run(ctx, data)
    assert len(findings) == 1
    assert findings[0].rule_id == "AD-SEC-000"


@pytest.mark.asyncio
async def test_safe_posture_plugin_silent_when_disabled() -> None:
    from adsec.rules.security.ad_sec_000_safe_posture import SafePostureCheck

    plugin = SafePostureCheck()
    ctx = ScanContext(
        engagement_id="ENG-1", scan_job_id="JOB-1", access_level=AccessLevel.AUDITOR, profile="safe"
    )
    data = NormalizedData(
        engagement_id="ENG-1",
        tables={"engagement_config": [{"intrusive_actions_enabled": False}]},
    )
    findings = await plugin.run(ctx, data)
    assert findings == []
