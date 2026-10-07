-- Migration 0001 : schema initial ADSEC (perimetre Phase 2).
-- Toutes les tables metier portent engagement_id pour garantir l'isolation
-- stricte entre engagements.

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER PRIMARY KEY,
    applied_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    metadata_json TEXT NOT NULL DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS engagements (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL REFERENCES clients(id) ON DELETE RESTRICT,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    default_profile TEXT NOT NULL,
    roe_reference TEXT,
    operator TEXT,
    created_at TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    config_hash TEXT,
    UNIQUE (client_id, name)
);

CREATE INDEX IF NOT EXISTS idx_engagements_client ON engagements(client_id);

CREATE TABLE IF NOT EXISTS scopes (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    entry_type TEXT NOT NULL,
    value TEXT NOT NULL,
    UNIQUE (engagement_id, entry_type, value)
);

CREATE INDEX IF NOT EXISTS idx_scopes_engagement ON scopes(engagement_id);

CREATE TABLE IF NOT EXISTS credentials_metadata (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    credential_type TEXT NOT NULL,
    principal TEXT,
    access_level_hint TEXT,
    secret_ref TEXT
);

CREATE INDEX IF NOT EXISTS idx_credentials_engagement ON credentials_metadata(engagement_id);

CREATE TABLE IF NOT EXISTS scan_jobs (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    profile TEXT NOT NULL,
    status TEXT NOT NULL,
    tool_version TEXT NOT NULL,
    plugin_versions_json TEXT NOT NULL DEFAULT '{}',
    configuration_hash TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    operator TEXT
);

CREATE INDEX IF NOT EXISTS idx_scan_jobs_engagement ON scan_jobs(engagement_id);

CREATE TABLE IF NOT EXISTS scan_events (
    id TEXT PRIMARY KEY,
    scan_job_id TEXT NOT NULL REFERENCES scan_jobs(id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    level TEXT NOT NULL,
    component TEXT NOT NULL,
    message TEXT NOT NULL,
    data_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_scan_events_job ON scan_events(scan_job_id);
