"""Modeles lies a l'execution d'un scan (traçabilite et reproductibilite)."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from pydantic import BaseModel, Field

from adsec.core.models.enums import CredentialType, LogLevel, ScanJobStatus, ScanProfile


def _now() -> datetime:
    return datetime.now(UTC)


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class CredentialsMetadata(BaseModel):
    """Metadonnees d'un moyen d'authentification utilise pour un engagement.

    Le secret lui-meme n'est JAMAIS stocke ici : `secret_ref` est un pointeur
    opaque resolu au moment de l'execution par un CredentialProvider
    (variable d'environnement, session Kerberos deja etablie, coffre externe).
    """

    id: str = Field(default_factory=lambda: _new_id("CRD"))
    engagement_id: str
    credential_type: CredentialType
    principal: str | None = None
    access_level_hint: str | None = None
    secret_ref: str | None = None

    def model_post_init(self, context: object, /) -> None:
        # Garde-fou defensif : si un champ ressemble a un secret en clair,
        # on refuse silencieusement de le conserver tel quel en le tronquant.
        forbidden_markers = ("password=", "secret=", "ticket=", "hash=")
        if self.secret_ref and any(m in self.secret_ref.lower() for m in forbidden_markers):
            raise ValueError(
                "secret_ref ne doit jamais contenir de secret en clair, "
                "uniquement une reference opaque"
            )


class ScanJob(BaseModel):
    """Une execution de scan donnee, tracable et reproductible."""

    id: str = Field(default_factory=lambda: _new_id("JOB"))
    engagement_id: str
    profile: ScanProfile
    status: ScanJobStatus = ScanJobStatus.PENDING
    tool_version: str
    plugin_versions: dict[str, str] = Field(default_factory=dict)
    configuration_hash: str
    started_at: datetime | None = None
    ended_at: datetime | None = None
    operator: str | None = None

    def duration_seconds(self) -> float | None:
        if self.started_at is None or self.ended_at is None:
            return None
        return (self.ended_at - self.started_at).total_seconds()


class ScanEvent(BaseModel):
    """Un evenement structure de log rattache a un scan_job (observabilite)."""

    id: str = Field(default_factory=lambda: _new_id("EVT"))
    scan_job_id: str
    timestamp: datetime = Field(default_factory=_now)
    level: LogLevel
    component: str
    message: str
    data: dict[str, object] = Field(default_factory=dict)
