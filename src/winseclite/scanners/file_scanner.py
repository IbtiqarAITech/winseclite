from __future__ import annotations
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from winseclite.config import AppConfig
from winseclite.core.models import Detection, FileScanResult, ObjectType
from winseclite.core.risk_score import severity_from_score
from winseclite.detection.hash_matcher import HashMatcher
from winseclite.detection.heuristics import analyze_script, path_location_score
from winseclite.detection.yara_matcher import YaraMatcher
from winseclite.storage.database import Database
from winseclite.utils.hashing import sha256_file


class FileScanner:
    """Defensive file scanner. Never executes files."""

    def __init__(self, config: AppConfig, db: Database, hash_matcher: HashMatcher, yara_matcher: YaraMatcher | None = None) -> None:
        self.config = config
        self.db = db
        self.hash_matcher = hash_matcher
        self.yara_matcher = yara_matcher

    def iter_files(self, roots: Iterable[Path]) -> Iterable[Path]:
        for root in roots:
            if not root.exists():
                continue
            if root.is_file():
                yield root
                continue
            for path in root.rglob("*"):
                try:
                    if not self.config.follow_symlinks and path.is_symlink():
                        continue
                    if path.is_file():
                        yield path
                except OSError:
                    continue

    def scan_file(self, path: Path) -> FileScanResult:
        detections: list[Detection] = []
        try:
            size = path.stat().st_size
        except OSError as exc:
            return FileScanResult(path, 0, None, [], str(exc))
        if size > self.config.max_file_size_bytes:
            return FileScanResult(path, size, None, [], f"File exceeds max scan size: {size} bytes")
        try:
            file_hash = sha256_file(path)
        except Exception as exc:
            return FileScanResult(path, size, None, [], str(exc))
        self.db.upsert_file_hash(file_hash, str(path), size)
        if self.hash_matcher.is_known_good(file_hash):
            return FileScanResult(path, size, file_hash, [])
        if self.hash_matcher.is_known_bad(file_hash):
            detections.append(Detection(ObjectType.FILE, str(path), 100, severity_from_score(100),
                                        "SHA256 matched known-bad signature database",
                                        "Quarantine and review. Submit to Defender for confirmation.",
                                        file_hash, "known_bad_sha256"))
        loc_score, loc_evidence = path_location_score(path)
        if loc_score:
            detections.append(Detection(ObjectType.FILE, str(path), loc_score, severity_from_score(loc_score),
                                        loc_evidence or "Suspicious file location", "Review origin and signer.",
                                        file_hash, "suspicious_location"))
        detections.extend(analyze_script(path, sha256=file_hash))
        if self.yara_matcher:
            for rule in self.yara_matcher.match_file(path):
                score = 75
                detections.append(Detection(ObjectType.FILE, str(path), score, severity_from_score(score),
                                            f"YARA rule matched: {rule}",
                                            "Quarantine only if untrusted; otherwise allowlist after review.",
                                            file_hash, f"yara:{rule}"))
        return FileScanResult(path, size, file_hash, detections)

    def scan_paths(self, roots: list[Path]) -> tuple[int, list[Detection]]:
        files = list(self.iter_files(roots))
        detections: list[Detection] = []
        scanned = 0
        with ThreadPoolExecutor(max_workers=self.config.max_workers) as pool:
            futures = [pool.submit(self.scan_file, p) for p in files]
            for future in as_completed(futures):
                result = future.result()
                if not result.skipped_reason:
                    scanned += 1
                detections.extend(result.detections)
        return scanned, detections
