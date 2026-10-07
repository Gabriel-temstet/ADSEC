"""Modeles des objets Active Directory collectes par les collectors LDAP.

Ces modeles representent une vue normalisee, independante du format brut
LDAP : les collectors sont responsables de la traduction attribut LDAP ->
champ type. `raw_attrs` conserve les attributs bruts pertinents pour
l'evidence et le debogage, sans dependre du schema LDAP dans le reste du
moteur.
"""

from __future__ import annotations

from uuid import uuid4

from pydantic import BaseModel, Field


def _new_id(prefix: str) -> str:
    return f"{prefix}-{uuid4().hex[:12]}"


class Forest(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("FOR"))
    engagement_id: str
    name: str
    functional_level: str | None = None


class Domain(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("DOM"))
    engagement_id: str
    forest_id: str | None = None
    fqdn: str
    netbios: str | None = None
    functional_level: str | None = None
    naming_context: str


class Site(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("SIT"))
    engagement_id: str
    domain_id: str
    name: str


class DomainController(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("DC"))
    engagement_id: str
    domain_id: str
    hostname: str
    ip: str | None = None
    is_global_catalog: bool = False
    os_version: str | None = None
    fsmo_roles: list[str] = Field(default_factory=list)


class OrganizationalUnit(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("OU"))
    engagement_id: str
    domain_id: str
    dn: str
    name: str
    parent_dn: str | None = None
    gplinks: list[str] = Field(default_factory=list)


class ADUser(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("USR"))
    engagement_id: str
    domain_id: str
    dn: str
    sam_account_name: str
    sid: str | None = None
    upn: str | None = None
    enabled: bool = True
    admin_count: bool = False
    password_never_expires: bool = False
    pre_auth_not_required: bool = False
    last_logon: str | None = None
    pwd_last_set: str | None = None
    spns: list[str] = Field(default_factory=list)
    raw_attrs: dict[str, object] = Field(default_factory=dict)


class ADGroup(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("GRP"))
    engagement_id: str
    domain_id: str
    dn: str
    sam_account_name: str
    sid: str | None = None
    privileged: bool = False
    raw_attrs: dict[str, object] = Field(default_factory=dict)


class GroupMembership(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("MBR"))
    engagement_id: str
    group_dn: str
    member_dn: str
    member_type: str  # "user" | "group" | "computer"
    nested: bool = False


class ADComputer(BaseModel):
    id: str = Field(default_factory=lambda: _new_id("CMP"))
    engagement_id: str
    domain_id: str
    dn: str
    sam_account_name: str
    sid: str | None = None
    dns_hostname: str | None = None
    operating_system: str | None = None
    enabled: bool = True
    unconstrained_delegation: bool = False
    raw_attrs: dict[str, object] = Field(default_factory=dict)


# Groupes AD reconnus comme privilegies par nom (heuristique de base,
# affinee dans les phases suivantes via SID bien connus / adminCount).
WELL_KNOWN_PRIVILEGED_GROUPS = frozenset(
    {
        "domain admins",
        "enterprise admins",
        "schema admins",
        "administrators",
        "account operators",
        "backup operators",
        "server operators",
        "print operators",
    }
)
