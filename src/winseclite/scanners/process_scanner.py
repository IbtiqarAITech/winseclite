from __future__ import annotations
from pathlib import Path
import psutil
from winseclite.core.models import Detection, ObjectType
from winseclite.core.risk_score import severity_from_score


class ProcessScanner:
    """Inspect running processes without tampering with them."""

    def scan(self) -> list[Detection]:
        detections: list[Detection] = []
        for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "username"]):
            try:
                info = proc.info
                exe = info.get("exe") or ""
                cmdline = " ".join(info.get("cmdline") or [])
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            lower_exe = exe.lower()
            lower_cmd = cmdline.lower()
            score = 0
            evidence: list[str] = []
            if lower_exe and any(part in lower_exe for part in ["\\temp\\", "\\appdata\\local\\temp\\"]):
                score += 25
                evidence.append("Process executable is in a temporary location")
            if "powershell" in lower_exe or "pwsh" in lower_exe:
                if "encodedcommand" in lower_cmd or " -enc " in lower_cmd:
                    score += 35
                    evidence.append("PowerShell process uses encoded command")
                if "downloadstring" in lower_cmd or "invoke-expression" in lower_cmd:
                    score += 30
                    evidence.append("PowerShell uses download or dynamic execution indicator")
            if score >= 30:
                detections.append(Detection(ObjectType.PROCESS, exe or info.get("name") or "unknown", min(score, 80),
                                            severity_from_score(score), "; ".join(evidence),
                                            "Review process path, parent, command line, and network activity.",
                                            metadata={"pid": info.get("pid"), "ppid": info.get("ppid"), "cmdline": cmdline,
                                                      "username": info.get("username"), "path_exists": bool(exe and Path(exe).exists())}))
        return detections
