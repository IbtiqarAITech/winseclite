CREATE TABLE IF NOT EXISTS scan_sessions (
    id TEXT PRIMARY KEY,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    scan_type TEXT NOT NULL,
    status TEXT NOT NULL,
    files_scanned INTEGER DEFAULT 0,
    detections_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS detections (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    detected_at TEXT NOT NULL,
    object_type TEXT NOT NULL,
    object_path TEXT,
    sha256 TEXT,
    rule_name TEXT,
    severity TEXT NOT NULL,
    risk_score INTEGER NOT NULL,
    evidence TEXT NOT NULL,
    recommended_action TEXT NOT NULL,
    status TEXT NOT NULL,
    metadata_json TEXT DEFAULT '{}',
    FOREIGN KEY(scan_id) REFERENCES scan_sessions(id)
);

CREATE TABLE IF NOT EXISTS file_hashes (
    sha256 TEXT PRIMARY KEY,
    file_path TEXT NOT NULL,
    size_bytes INTEGER,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signatures (
    id TEXT PRIMARY KEY,
    signature_type TEXT NOT NULL,
    value TEXT NOT NULL,
    family TEXT,
    severity TEXT,
    source TEXT,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS quarantine_items (
    id TEXT PRIMARY KEY,
    original_path TEXT NOT NULL,
    quarantine_path TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    quarantined_at TEXT NOT NULL,
    detection_id TEXT NOT NULL,
    restore_status TEXT DEFAULT 'not_restored'
);

CREATE INDEX IF NOT EXISTS idx_detections_scan_id ON detections(scan_id);
CREATE INDEX IF NOT EXISTS idx_detections_sha256 ON detections(sha256);
CREATE INDEX IF NOT EXISTS idx_signatures_type_value ON signatures(signature_type, value);
