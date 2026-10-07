-- Migration 0003 : perimetre Phase 4, lot 1 (ACL + trusts).
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS acls (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    object_dn TEXT NOT NULL,
    object_type TEXT NOT NULL,
    owner_sid TEXT,
    UNIQUE (engagement_id, object_dn)
);

CREATE INDEX IF NOT EXISTS idx_acls_engagement ON acls(engagement_id);

CREATE TABLE IF NOT EXISTS permissions (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    acl_id TEXT NOT NULL REFERENCES acls(id) ON DELETE CASCADE,
    trustee_sid TEXT NOT NULL,
    ace_type TEXT NOT NULL,
    rights_mask INTEGER NOT NULL,
    rights_json TEXT NOT NULL DEFAULT '[]',
    object_type_guid TEXT,
    inherited INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_permissions_engagement ON permissions(engagement_id);
CREATE INDEX IF NOT EXISTS idx_permissions_acl ON permissions(acl_id);
CREATE INDEX IF NOT EXISTS idx_permissions_trustee ON permissions(engagement_id, trustee_sid);

CREATE TABLE IF NOT EXISTS trusts (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    domain_id TEXT NOT NULL REFERENCES domains(id) ON DELETE CASCADE,
    trust_partner TEXT NOT NULL,
    direction TEXT NOT NULL,
    trust_type TEXT NOT NULL,
    transitive INTEGER NOT NULL DEFAULT 0,
    sid_filtering INTEGER NOT NULL DEFAULT 0,
    raw_attrs_json TEXT NOT NULL DEFAULT '{}',
    UNIQUE (engagement_id, trust_partner)
);

CREATE INDEX IF NOT EXISTS idx_trusts_engagement ON trusts(engagement_id);
