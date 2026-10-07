-- Migration 0002 : perimetre Phase 3 (LDAP discovery).
-- Additive uniquement : ne modifie jamais 0001_initial.sql retroactivement.

CREATE TABLE IF NOT EXISTS forests (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    functional_level TEXT
);

CREATE INDEX IF NOT EXISTS idx_forests_engagement ON forests(engagement_id);

CREATE TABLE IF NOT EXISTS domains (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    forest_id TEXT REFERENCES forests(id) ON DELETE SET NULL,
    fqdn TEXT NOT NULL,
    netbios TEXT,
    functional_level TEXT,
    naming_context TEXT NOT NULL,
    UNIQUE (engagement_id, fqdn)
);

CREATE INDEX IF NOT EXISTS idx_domains_engagement ON domains(engagement_id);

CREATE TABLE IF NOT EXISTS sites (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    name TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sites_engagement ON sites(engagement_id);

CREATE TABLE IF NOT EXISTS domain_controllers (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    ip TEXT,
    is_global_catalog INTEGER NOT NULL DEFAULT 0,
    os_version TEXT,
    fsmo_roles_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (engagement_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_dcs_engagement ON domain_controllers(engagement_id);

CREATE TABLE IF NOT EXISTS ous (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    dn TEXT NOT NULL,
    name TEXT NOT NULL,
    parent_dn TEXT,
    gplink_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (engagement_id, dn)
);

CREATE INDEX IF NOT EXISTS idx_ous_engagement ON ous(engagement_id);

CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    dn TEXT NOT NULL,
    sam_account_name TEXT NOT NULL,
    sid TEXT,
    upn TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    admin_count INTEGER NOT NULL DEFAULT 0,
    password_never_expires INTEGER NOT NULL DEFAULT 0,
    pre_auth_not_required INTEGER NOT NULL DEFAULT 0,
    last_logon TEXT,
    pwd_last_set TEXT,
    spns_json TEXT NOT NULL DEFAULT '[]',
    raw_attrs_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (engagement_id, dn)
);

CREATE INDEX IF NOT EXISTS idx_users_engagement ON users(engagement_id);
CREATE INDEX IF NOT EXISTS idx_users_sam ON users(engagement_id, sam_account_name);

CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    dn TEXT NOT NULL,
    sam_account_name TEXT NOT NULL,
    sid TEXT,
    privileged INTEGER NOT NULL DEFAULT 0,
    raw_attrs_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (engagement_id, dn)
);

CREATE INDEX IF NOT EXISTS idx_groups_engagement ON groups(engagement_id);

CREATE TABLE IF NOT EXISTS group_memberships (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    group_dn TEXT NOT NULL,
    member_dn TEXT NOT NULL,
    member_type TEXT NOT NULL,
    nested INTEGER NOT NULL DEFAULT 0,
    UNIQUE (engagement_id, group_dn, member_dn)
);

CREATE INDEX IF NOT EXISTS idx_memberships_engagement ON group_memberships(engagement_id);
CREATE INDEX IF NOT EXISTS idx_memberships_group ON group_memberships(engagement_id, group_dn);
CREATE INDEX IF NOT EXISTS idx_memberships_member ON group_memberships(engagement_id, member_dn);

CREATE TABLE IF NOT EXISTS computers (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    dn TEXT NOT NULL,
    sam_account_name TEXT NOT NULL,
    sid TEXT,
    dns_hostname TEXT,
    operating_system TEXT,
    enabled INTEGER NOT NULL DEFAULT 1,
    unconstrained_delegation INTEGER NOT NULL DEFAULT 0,
    raw_attrs_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (engagement_id, dn)
);

CREATE INDEX IF NOT EXISTS idx_computers_engagement ON computers(engagement_id);
