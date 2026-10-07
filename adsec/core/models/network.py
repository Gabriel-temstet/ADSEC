"""Modeles des observations SMB et DNS."""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class SmbShare(BaseModel):
    name: str
    remark: str = ""
    is_hidden_admin_share: bool = False
    anonymous_readable: bool = False


class SmbHost(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("SMB"))
    engagement_id: str
    hostname: str
    dialect: str | None = None
    is_smb1: bool = False
    signing_required: bool = False
    guest_or_anonymous: bool = False
    shares: list[SmbShare] = Field(default_factory=list)


class DnsZoneCheck(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("DNS"))
    engagement_id: str
    zone: str
    zone_transfer_allowed: bool = False
    zone_transfer_record_count: int = 0
    recursion_available: bool = False
