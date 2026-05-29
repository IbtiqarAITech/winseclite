from __future__ import annotations
import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from winseclite.core.models import Detection, ScanSession


class Database:
    """SQLite persistence layer using WAL for GUI/scan concurrency."""

    def __init__(self, db_path: Path, schema_path: Path | None = None) -> None:
        self.db_path = db_path
        self.schema_path = schema_path or Path(__file__).with_name("schema.sql")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        con = sqlite3.connect(self.db_path)
        con.execute("PRAGMA journal_mode=WAL;")
        con.execute("PRAGMA foreign_keys=ON;")
        return con

    def init(self) -> None:
        with self.connect() as con:
            con.executescript(self.schema_path.read_text(encoding="utf-8"))

    def save_scan_session(self, session: ScanSession) -> None:
        with self.connect() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO scan_sessions
                (id, started_at, finished_at, scan_type, status, files_scanned, detections_count)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (session.id, session.started_at.isoformat(), session.finished_at.isoformat() if session.finished_at else None,
                 session.scan_type, session.status, session.files_scanned, session.detections_count),
            )

    def save_detection(self, detection: Detection) -> None:
        if not detection.scan_id:
            raise ValueError("detection.scan_id is required before saving")
        with self.connect() as con:
            con.execute(
                """
                INSERT OR REPLACE INTO detections
                (id, scan_id, detected_at, object_type, object_path, sha256, rule_name,
                 severity, risk_score, evidence, recommended_action, status, metadata_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (detection.id, detection.scan_id, detection.detected_at.isoformat(), detection.object_type.value,
                 detection.object_path, detection.sha256, detection.rule_name, detection.severity.value,
                 detection.risk_score, detection.evidence, detection.recommended_action, detection.status.value,
                 json.dumps(detection.metadata, ensure_ascii=False)),
            )

    def upsert_file_hash(self, sha256: str, file_path: str, size_bytes: int) -> None:
        now = datetime.now(UTC).isoformat()
        with self.connect() as con:
            con.execute(
                """
                INSERT INTO file_hashes (sha256, file_path, size_bytes, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(sha256) DO UPDATE SET
                    file_path=excluded.file_path,
                    size_bytes=excluded.size_bytes,
                    last_seen=excluded.last_seen
                """,
                (sha256, file_path, size_bytes, now, now),
            )

    def list_recent_detections(self, limit: int = 100) -> list[dict]:
        with self.connect() as con:
            con.row_factory = sqlite3.Row
            rows = con.execute("SELECT * FROM detections ORDER BY detected_at DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]
