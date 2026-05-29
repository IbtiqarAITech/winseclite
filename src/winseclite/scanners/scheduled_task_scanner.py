from __future__ import annotations
import csv
import io
import subprocess
from winseclite.core.models import Detection, ObjectType
from winseclite.core.risk_score import severity_from_score
from winseclite.utils.platform import is_windows


class ScheduledTaskScanner:
    """Read-only scheduled task scanner using schtasks."""

    def scan(self) -> list[Detection]:
        if not is_windows():
            return []
        try:
            proc = subprocess.run(["schtasks", "/Query", "/FO", "CSV", "/V"], capture_output=True,
                                  text=True, encoding="utf-8", errors="ignore", timeout=60, check=False)
        except Exception:
            return []
        if proc.returncode != 0 or not proc.stdout:
            return []
        detections: list[Detection] = []
        for row in csv.DictReader(io.StringIO(proc.stdout)):
            task_name = row.get("TaskName") or "unknown"
            action = row.get("Task To Run") or ""
            score, evidence = self._score_action(action)
            if score >= 30:
                detections.append(Detection(ObjectType.SCHEDULED_TASK, task_name, score, severity_from_score(score),
                                            evidence, "Review task action, author, trigger, and creation time.",
                                            rule_name="scheduled_task_heuristics", metadata={"task_to_run": action}))
        return detections

    @staticmethod
    def _score_action(action: str) -> tuple[int, str]:
        lower = action.lower()
        score = 0
        evidence: list[str] = []
        if any(x in lower for x in ["\\temp\\", "%temp%", "downloads", "appdata"]):
            score += 30; evidence.append("Task action references user-writable or temporary location")
        if any(x in lower for x in ["powershell", "wscript", "cscript", "mshta", "cmd.exe /c"]):
            score += 25; evidence.append("Task action uses script interpreter or shell")
        if "encodedcommand" in lower or " -enc " in lower:
            score += 35; evidence.append("Task action contains encoded PowerShell indicator")
        return min(score, 90), "; ".join(evidence) or "Suspicious task action"
