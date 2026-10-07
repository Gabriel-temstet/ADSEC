-- Migration 0009 : baselines pour le diff entre scans (Phase 7).
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS baselines (
    id TEXT PRIMARY KEY,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    label TEXT NOT NULL,
    created_at TEXT NOT NULL,
    finding_fingerprints_json TEXT NOT NULL DEFAULT '[]',
    object_counts_json TEXT NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_baselines_engagement ON baselines(engagement_id);
