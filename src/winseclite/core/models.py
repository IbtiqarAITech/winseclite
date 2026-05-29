from __future__ import annotations
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ObjectType(str, Enum):
    FILE = "file"
    SCRIPT = "script"
    PROCESS = "process"
    REGISTRY = "registry"
    SCHEDULED_TASK = "scheduled_task"
    SERVICE = "service"
    NETWORK = "network"
    BROWSER = "browser"


class DetectionStatus(str, Enum):
    DETECTED = "detected"
    QUARANTINED = "quarantined"
    IGNORED = "ignored"
    RESTORED = "restored"


@dataclass(slots=True)
class Detection:
    object_type: ObjectType
    object_path: str
    risk_score: int
    severity: Severity
    evidence: str
    recommended_action: str
    sha256: str | None = None
    rule_name: str | None = None
    id: str = field(default_factory=lambda: str(uuid4()))
    scan_id: str | None = None
    detected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    status: DetectionStatus = DetectionStatus.DETECTED
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ScanSession:
    scan_type: str
    id: str = field(default_factory=lambda: str(uuid4()))
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    finished_at: datetime | None = None
    status: str = "running"
    files_scanned: int = 0
    detections_count: int = 0


@dataclass(slots=True)
class FileScanResult:
    path: Path
    size_bytes: int
    sha256: str | None
    detections: list[Detection]
    skipped_reason: str | None = None
