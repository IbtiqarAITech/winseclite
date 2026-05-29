from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path
from winseclite.config import AppConfig
from winseclite.core.models import Detection, ScanSession
from winseclite.core.paths import quick_scan_paths
from winseclite.detection.hash_matcher import HashMatcher
from winseclite.detection.yara_matcher import YaraMatcher
from winseclite.reporting.report_builder import ReportBuilder
from winseclite.scanners.file_scanner import FileScanner
from winseclite.scanners.network_scanner import NetworkScanner
from winseclite.scanners.process_scanner import ProcessScanner
from winseclite.scanners.registry_scanner import RegistryScanner
from winseclite.scanners.scheduled_task_scanner import ScheduledTaskScanner
from winseclite.scanners.service_scanner import ServiceScanner
from winseclite.storage.database import Database
logger = logging.getLogger(__name__)


class ScanOrchestrator:
    """Coordinates scanner modules and persistence."""

    def __init__(self, config: AppConfig, db: Database) -> None:
        self.config = config
        self.db = db
        self.report_builder = ReportBuilder(config.report_dir)
        self.file_scanner = FileScanner(config, db, HashMatcher.from_directory(config.hashes_dir), YaraMatcher(config.yara_dir, enabled=config.enable_yara))
        self.process_scanner = ProcessScanner()
        self.registry_scanner = RegistryScanner()
        self.task_scanner = ScheduledTaskScanner()
        self.service_scanner = ServiceScanner()
        self.network_scanner = NetworkScanner()

    def run_quick_scan(self, report_format: str = "json") -> tuple[ScanSession, list[Detection], Path | None]:
        return self.run_custom_scan(quick_scan_paths(), "quick", report_format)

    def run_custom_scan(self, roots: list[Path], scan_type: str = "custom", report_format: str = "json") -> tuple[ScanSession, list[Detection], Path | None]:
        session = ScanSession(scan_type=scan_type)
        self.db.save_scan_session(session)
        detections: list[Detection] = []
        try:
            session.files_scanned, file_detections = self.file_scanner.scan_paths(roots)
            detections.extend(file_detections)
            for name, scanner in [("process", self.process_scanner), ("registry", self.registry_scanner),
                                  ("scheduled_task", self.task_scanner), ("service", self.service_scanner),
                                  ("network", self.network_scanner)]:
                try:
                    detections.extend(scanner.scan())
                except Exception as exc:
                    logger.exception("%s scanner failed: %s", name, exc)
            for d in detections:
                d.scan_id = session.id
                self.db.save_detection(d)
            session.detections_count = len(detections)
            session.status = "completed"
            session.finished_at = datetime.now(timezone.utc)
            self.db.save_scan_session(session)
            report_path: Path | None = None
            if report_format == "html":
                report_path = self.report_builder.write_html(session, detections)
            elif report_format == "json":
                report_path = self.report_builder.write_json(session, detections)
            elif report_format == "both":
                self.report_builder.write_json(session, detections)
                report_path = self.report_builder.write_html(session, detections)
            return session, detections, report_path
        except Exception:
            session.status = "failed"
            session.finished_at = datetime.now(timezone.utc)
            self.db.save_scan_session(session)
            raise
