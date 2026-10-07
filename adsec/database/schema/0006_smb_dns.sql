-- Migration 0006 : inventaire SMB et DNS (Phase 4, lot 3).
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS smb_hosts (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    hostname TEXT NOT NULL,
    dialect TEXT,
    is_smb1 INTEGER NOT NULL DEFAULT 0,
    signing_required INTEGER NOT NULL DEFAULT 0,
    guest_or_anonymous INTEGER NOT NULL DEFAULT 0,
    UNIQUE (engagement_id, hostname)
);

CREATE INDEX IF NOT EXISTS idx_smb_hosts_engagement ON smb_hosts(engagement_id);

CREATE TABLE IF NOT EXISTS smb_shares (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    host_id TEXT NOT NULL REFERENCES smb_hosts(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    remark TEXT,
    is_hidden_admin_share INTEGER NOT NULL DEFAULT 0,
    anonymous_readable INTEGER NOT NULL DEFAULT 0,
    UNIQUE (engagement_id, host_id, name)
);

CREATE INDEX IF NOT EXISTS idx_smb_shares_engagement ON smb_shares(engagement_id);

CREATE TABLE IF NOT EXISTS dns_zone_checks (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    zone TEXT NOT NULL,
    zone_transfer_allowed INTEGER NOT NULL DEFAULT 0,
    zone_transfer_record_count INTEGER NOT NULL DEFAULT 0,
    recursion_available INTEGER NOT NULL DEFAULT 0,
    UNIQUE (engagement_id, zone)
);

CREATE INDEX IF NOT EXISTS idx_dns_zone_checks_engagement ON dns_zone_checks(engagement_id);
