from __future__ import annotations

import pytest

from adsec.core.models.engagement import Scope
from adsec.core.scope.scope_manager import OutOfScopeError, ScopeManager


def make_scope(**kwargs: object) -> Scope:
    return Scope(engagement_id="ENG-test", **kwargs)


def test_domain_inclusion_matches_subdomains() -> None:
    scope = make_scope(domains=["acme.local"])
    manager = ScopeManager(scope)
    assert manager.is_in_scope("dc01.acme.local")
    assert manager.is_in_scope("acme.local")
    assert not manager.is_in_scope("acme.local.evil.com")


def test_host_glob_inclusion() -> None:
    scope = make_scope(hosts_include=["*.acme.local"])
    manager = ScopeManager(scope)
    assert manager.is_in_scope("dc01.acme.local")
    assert not manager.is_in_scope("dc01.other.local")


def test_exclusion_wins_over_inclusion() -> None:
    scope = make_scope(
        domains=["acme.local"],
        hosts_exclude=["production.acme.local"],
    )
    manager = ScopeManager(scope)
    assert manager.is_in_scope("dc01.acme.local")
    assert not manager.is_in_scope("production.acme.local")


def test_network_inclusion_and_exclusion() -> None:
    scope = make_scope(
        networks_include=["10.10.0.0/16"],
        networks_exclude=["10.10.5.0/24"],
    )
    manager = ScopeManager(scope)
    assert manager.is_in_scope("10.10.1.1")
    assert not manager.is_in_scope("10.10.5.42")
    assert not manager.is_in_scope("192.168.1.1")


def test_ip_literal_is_not_matched_by_domain_or_host_rules() -> None:
    scope = make_scope(domains=["acme.local"], hosts_include=["*.acme.local"])
    manager = ScopeManager(scope)
    assert not manager.is_in_scope("10.10.1.1")


def test_assert_in_scope_raises_for_out_of_scope_target() -> None:
    scope = make_scope(domains=["acme.local"])
    manager = ScopeManager(scope)
    with pytest.raises(OutOfScopeError):
        manager.assert_in_scope("evil.com")


def test_assert_in_scope_does_not_raise_for_in_scope_target() -> None:
    scope = make_scope(domains=["acme.local"])
    manager = ScopeManager(scope)
    manager.assert_in_scope("dc01.acme.local")  # ne doit pas lever


def test_intrusive_actions_disabled_by_default() -> None:
    scope = make_scope(domains=["acme.local"])
    manager = ScopeManager(scope)
    assert not manager.intrusive_allowed()
    with pytest.raises(OutOfScopeError):
        manager.assert_intrusive_allowed("ForceChangePassword")


def test_intrusive_actions_allowed_when_enabled() -> None:
    scope = make_scope(domains=["acme.local"], intrusive_actions_enabled=True)
    manager = ScopeManager(scope)
    assert manager.intrusive_allowed()
    manager.assert_intrusive_allowed("ForceChangePassword")  # ne doit pas lever


def test_invalid_network_in_scope_raises_validation_error() -> None:
    with pytest.raises(ValueError):
        make_scope(networks_include=["not-a-network"])
