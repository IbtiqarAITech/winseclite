from __future__ import annotations
import json
import subprocess
from winseclite.core.models import Detection, ObjectType
from winseclite.core.risk_score import severity_from_score
from winseclite.utils.platform import is_windows


class ServiceScanner:
    """Read-only service scanner. Does not stop or modify services."""

    def scan(self) -> list[Detection]:
        if not is_windows():
            return []
        command = "Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName | ConvertTo-Json -Depth 3"
        try:
            proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                                  capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=60, check=False)
        except Exception:
            return []
        if proc.returncode != 0 or not proc.stdout.strip():
            return []
        try:
            data = json.loads(proc.stdout)
        except json.JSONDecodeError:
            return []
        services = data if isinstance(data, list) else [data]
        detections: list[Detection] = []
        for svc in services:
            score, evidence = self._score_path(str(svc.get("PathName") or ""))
            if score >= 30:
                detections.append(Detection(ObjectType.SERVICE, str(svc.get("Name") or "unknown"), score,
                                            severity_from_score(score), evidence,
                                            "Review service binary path and vendor before changing anything.",
                                            rule_name="service_path_heuristics", metadata=svc))
        return detections

    @staticmethod
    def _score_path(path: str) -> tuple[int, str]:
        lower = path.lower()
        score = 0
        evidence: list[str] = []
        if any(x in lower for x in ["\\temp\\", "downloads", "appdata"]):
            score += 35; evidence.append("Service path references user-writable or temporary location")
        if lower and " " in lower and not lower.strip().startswith('"') and lower.endswith(".exe"):
            score += 25; evidence.append("Service path appears unquoted and contains spaces")
        return min(score, 80), "; ".join(evidence) or "Suspicious service path"
