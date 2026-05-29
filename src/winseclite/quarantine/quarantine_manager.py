from __future__ import annotations
import json
import os
import shutil
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4
from winseclite.core.models import Detection, DetectionStatus
from winseclite.utils.hashing import sha256_file


class QuarantineManager:
    """File quarantine manager. It renames payloads to a non-executable suffix."""

    def __init__(self, quarantine_dir: Path) -> None:
        self.quarantine_dir = quarantine_dir
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

    def quarantine_file(self, detection: Detection) -> Path:
        source = Path(detection.object_path).resolve()
        if not source.exists() or not source.is_file():
            raise FileNotFoundError(source)
        item_id = str(uuid4())
        item_dir = self.quarantine_dir / item_id
        item_dir.mkdir(parents=True, exist_ok=False)
        original_hash = sha256_file(source)
        quarantine_path = item_dir / "payload.quarantined"
        metadata_path = item_dir / "metadata.json"
        shutil.move(str(source), str(quarantine_path))
        try:
            os.chmod(quarantine_path, 0o600)
        except Exception:
            pass
        metadata = {"id": item_id, "original_path": str(source), "quarantine_path": str(quarantine_path),
                    "sha256": original_hash, "detection_id": detection.id,
                    "quarantined_at": datetime.now(timezone.utc).isoformat(),
                    "detection": {"rule_name": detection.rule_name, "risk_score": detection.risk_score,
                                  "severity": detection.severity.value, "evidence": detection.evidence}}
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        detection.status = DetectionStatus.QUARANTINED
        return quarantine_path

    def list_items(self) -> list[dict]:
        items = []
        for metadata_path in self.quarantine_dir.glob("*/metadata.json"):
            try:
                items.append(json.loads(metadata_path.read_text(encoding="utf-8")))
            except Exception:
                continue
        return items

    def restore(self, item_id: str, restore_to: Path | None = None) -> Path:
        item_dir = (self.quarantine_dir / item_id).resolve()
        if self.quarantine_dir.resolve() not in item_dir.parents:
            raise ValueError("Invalid quarantine item id")
        metadata_path = item_dir / "metadata.json"
        payload_path = item_dir / "payload.quarantined"
        if not metadata_path.exists() or not payload_path.exists():
            raise FileNotFoundError(item_id)
        metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
        target = (restore_to or Path(metadata["original_path"])).resolve()
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(payload_path), str(target))
        metadata["restore_status"] = "restored"
        metadata["restored_at"] = datetime.now(timezone.utc).isoformat()
        metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")
        return target
