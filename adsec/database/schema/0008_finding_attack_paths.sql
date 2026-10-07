-- Migration 0008 : correlation findings <-> chemins d'attaque (Phase 5, lot 2).
-- Additive uniquement.

CREATE TABLE IF NOT EXISTS finding_attack_paths (
    finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
    attack_path_id TEXT NOT NULL REFERENCES attack_paths(id) ON DELETE CASCADE,
    engagement_id TEXT NOT NULL REFERENCES engagements(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, attack_path_id)
);

CREATE INDEX IF NOT EXISTS idx_finding_attack_paths_engagement ON finding_attack_paths(engagement_id);
CREATE INDEX IF NOT EXISTS idx_finding_attack_paths_finding ON finding_attack_paths(finding_id);
CREATE INDEX IF NOT EXISTS idx_finding_attack_paths_path ON finding_attack_paths(attack_path_id);
