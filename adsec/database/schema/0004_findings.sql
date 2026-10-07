-- Migration 0004 : persistance des findings et de leurs preuves (Phase 4).
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    scan_job_id TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    rule_id TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    severity TEXT NOT NULL,
    confidence TEXT NOT NULL,
    status TEXT NOT NULL,
    affected_assets_json TEXT NOT NULL DEFAULT '[]',
    description TEXT NOT NULL,
    technical_details TEXT NOT NULL,
    impact TEXT NOT NULL,
    validation_procedure TEXT NOT NULL,
    remediation TEXT NOT NULL,
    references_json TEXT NOT NULL DEFAULT '[]',
    mitre_technique_id TEXT,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    UNIQUE (engagement_id, fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_engagement ON findings(engagement_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(engagement_id, rule_id);

CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    source TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_id TEXT NOT NULL,
    attribute TEXT NOT NULL,
    value TEXT NOT NULL,
    hash TEXT NOT NULL,
    collector_version TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_evidence_engagement ON evidence(engagement_id);
CREATE INDEX IF NOT EXISTS idx_evidence_finding ON evidence(finding_id);
