"""Modele GPO (Group Policy Object) : metadonnees LDAP et liens."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field


class GpoLink(BaseModel):
    """Un lien de cette GPO vers un conteneur (domaine racine ou OU)."""

    target_dn: str
    enabled: bool = True
    enforced: bool = False


class GroupPolicy(BaseModel):
    id: str = Field(default_factory=lambda: f"GPO-{uuid4().hex[:12]}")
    engagement_id: str
    domain_id: str
    guid: str
    dn: str
    display_name: str
    file_sys_path: str | None = None
    version_number: int = 0
    flags: int = 0  # 0 actif, 1 config utilisateur off, 2 config ordinateur off, 3 tout off
    links: list[GpoLink] = Field(default_factory=list)

    @property
    def fully_disabled(self) -> bool:
        return self.flags == 3
