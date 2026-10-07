"""Modeles ACL (permissions sur les objets AD) et relations de confiance
(trusts) entre domaines/forets."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class Permission(BaseModel):
    """Une ACE (Access Control Entry) individuelle, deja decodee."""

    id: str = Field(default_factory=lambda: _new_id("PRM"))
    trustee_sid: str
    ace_type: str  # ALLOWED | DENIED | ALLOWED_OBJECT | DENIED_OBJECT
    rights_mask: int
    rights: list[str] = Field(default_factory=list)
    object_type_guid: str | None = None
    resolved_right_name: str | None = None
    inherited: bool = False


class Acl(BaseModel):
    """L'ACL complete (DACL) d'un objet AD, avec ses permissions decodees."""

    id: str = Field(default_factory=lambda: _new_id("ACL"))
    engagement_id: str
    object_dn: str
    object_type: str  # user | group | computer | ou
    owner_sid: str | None = None
    permissions: list[Permission] = Field(default_factory=list)


class Trust(BaseModel):
    """Une relation de confiance (trust) vers un autre domaine/foret."""

    id: str = Field(default_factory=lambda: _new_id("TRU"))
    engagement_id: str
    domain_id: str
    trust_partner: str
    direction: str  # inbound | outbound | bidirectional
    trust_type: str  # downlevel | uplevel | mit | dce
    transitive: bool = False
    sid_filtering: bool = False
    raw_attrs: dict[str, object] = Field(default_factory=dict)
