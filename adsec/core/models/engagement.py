"""Modeles Client, Engagement et Scope.

Un Engagement est l'unite de travail centrale d'ADSEC : toutes les donnees
collectees, tous les findings et tous les rapports sont rattaches a un
engagement_id, ce qui garantit qu'aucune donnee de deux missions ne peut
etre melangee accidentellement.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field, field_validator

from adsec.core.models.enums import EngagementStatus, ScanProfile, ScopeEntryType


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class Client(BaseModel):
    """Un client du cabinet (ex: ACME)."""

    id: str = Field(default_factory=lambda: _new_id("CLI"))
    name: str
    created_at: datetime = Field(default_factory=_now)
    metadata: dict[str, str] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _name_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("Le nom du client ne peut pas etre vide")
        return v


class ScopeEntry(BaseModel):
    """Une entree individuelle de scope (domaine, host, reseau, exclusion)."""

    id: str = Field(default_factory=lambda: _new_id("SCP"))
    engagement_id: str
    entry_type: ScopeEntryType
    value: str

    @field_validator("value")
    @classmethod
    def _validate_value(cls, v: str, info: object) -> str:
        v = v.strip()
        if not v:
            raise ValueError("La valeur de scope ne peut pas etre vide")
        return v


class Scope(BaseModel):
    """Vue agregee du scope d'un engagement, utilisee par le ScopeManager."""

    engagement_id: str
    domains: list[str] = Field(default_factory=list)
    hosts_include: list[str] = Field(default_factory=list)
    hosts_exclude: list[str] = Field(default_factory=list)
    networks_include: list[str] = Field(default_factory=list)
    networks_exclude: list[str] = Field(default_factory=list)
    intrusive_actions_enabled: bool = False

    @field_validator("networks_include", "networks_exclude")
    @classmethod
    def _validate_networks(cls, values: list[str]) -> list[str]:
        for v in values:
            try:
                ipaddress.ip_network(v, strict=False)
            except ValueError as exc:
                raise ValueError(f"Reseau invalide dans le scope: {v!r}") from exc
        return values

    @classmethod
    def from_entries(cls, engagement_id: str, entries: list[ScopeEntry]) -> Scope:
        scope = cls(engagement_id=engagement_id)
        for entry in entries:
            match entry.entry_type:
                case ScopeEntryType.DOMAIN:
                    scope.domains.append(entry.value)
                case ScopeEntryType.HOST_INCLUDE:
                    scope.hosts_include.append(entry.value)
                case ScopeEntryType.HOST_EXCLUDE:
                    scope.hosts_exclude.append(entry.value)
                case ScopeEntryType.NETWORK_INCLUDE:
                    scope.networks_include.append(entry.value)
                case ScopeEntryType.NETWORK_EXCLUDE:
                    scope.networks_exclude.append(entry.value)
        return scope

    def is_empty(self) -> bool:
        return not (self.domains or self.hosts_include or self.networks_include)


_ENGAGEMENT_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,63}$")


class Engagement(BaseModel):
    """Une mission pour un client donne."""

    id: str = Field(default_factory=lambda: _new_id("ENG"))
    client_id: str
    name: str
    status: EngagementStatus = EngagementStatus.DRAFT
    default_profile: ScanProfile = ScanProfile.SAFE
    roe_reference: str | None = None
    operator: str | None = None
    created_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    ended_at: datetime | None = None
    config_hash: str | None = None

    @field_validator("name")
    @classmethod
    def _validate_name(cls, v: str) -> str:
        v = v.strip()
        if not _ENGAGEMENT_NAME_RE.match(v):
            raise ValueError(
                "Le nom d'engagement doit etre alphanumerique "
                "(., _, - autorises), 2 a 64 caracteres"
            )
        return v
