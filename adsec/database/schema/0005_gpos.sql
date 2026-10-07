-- Migration 0005 : GPO (metadonnees et liens, collecte LDAP) - Phase 4, lot 2.
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS gpos (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    guid TEXT NOT NULL,
    dn TEXT NOT NULL,
    display_name TEXT NOT NULL,
    file_sys_path TEXT,
    version_number INTEGER NOT NULL DEFAULT 0,
    flags INTEGER NOT NULL DEFAULT 0,
    links_json TEXT NOT NULL DEFAULT '[]',
    UNIQUE (engagement_id, guid)
);

CREATE INDEX IF NOT EXISTS idx_gpos_engagement ON gpos(engagement_id);
