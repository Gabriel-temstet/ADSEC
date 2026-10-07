-- Migration 0007 : persistance des chemins d'attaque calcules (Phase 5, lot 1).
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS attack_paths (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    scan_job_id TEXT REFERENCES scan_jobs(id) ON DELETE SET NULL,
    source_id TEXT NOT NULL,
    target_id TEXT NOT NULL,
    length INTEGER NOT NULL,
    confidence TEXT NOT NULL,
    impact_summary TEXT NOT NULL DEFAULT '',
    node_ids_json TEXT NOT NULL DEFAULT '[]',
    edges_json TEXT NOT NULL DEFAULT '[]',
    computed_at TEXT NOT NULL,
    UNIQUE (engagement_id, source_id, target_id)
);

CREATE INDEX IF NOT EXISTS idx_attack_paths_engagement ON attack_paths(engagement_id);
CREATE INDEX IF NOT EXISTS idx_attack_paths_target ON attack_paths(engagement_id, target_id);
