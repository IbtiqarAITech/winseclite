from __future__ import annotations
import math
import re
from pathlib import Path
from winseclite.core.models import Detection, ObjectType
from winseclite.core.risk_score import severity_from_score

SCRIPT_EXTENSIONS = {".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".js", ".jse", ".wsf", ".hta", ".sh", ".bash"}
EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".scr", ".msi", ".com"}
RISKY_DIR_NAMES = {"temp", "tmp", "downloads", "desktop", "appdata", "programdata"}
SUSPICIOUS_SCRIPT_PATTERNS: list[tuple[str, int, str]] = [
    (r"(?i)encodedcommand|\s-enc\s", 35, "PowerShell encoded command indicator"),
    (r"(?i)frombase64string", 25, "Base64 decoding indicator"),
    (r"(?i)downloadstring|invoke-webrequest|curl\s+http|wget\s+http", 25, "Download behavior"),
    (r"(?i)iex\s*\(|invoke-expression", 30, "Dynamic execution indicator"),
    (r"(?i)add-mppreference|set-mppreference", 20, "Defender preference modification command"),
    (r"(?i)reg\s+add\s+.*currentversion\\run", 25, "Registry Run persistence command"),
    (r"(?i)schtasks\s+/create|new-scheduledtask", 25, "Scheduled task creation command"),
    (r"(?i)start-process\s+.*-windowstyle\s+hidden", 20, "Hidden process execution"),
]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {c: text.count(c) for c in set(text)}
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def path_location_score(path: Path) -> tuple[int, str | None]:
    parts = {part.lower() for part in path.parts}
    suffix = path.suffix.lower()
    if suffix in EXECUTABLE_EXTENSIONS and parts.intersection(RISKY_DIR_NAMES):
        return 25, "Executable file located in a user-writable or temporary location"
    if suffix in SCRIPT_EXTENSIONS and parts.intersection({"startup", "temp", "downloads"}):
        return 20, "Script located in a startup, temporary, or downloads location"
    return 0, None


def analyze_script(path: Path, sha256: str | None = None) -> list[Detection]:
    """Read-only script analysis. The script is never executed."""
    if path.suffix.lower() not in SCRIPT_EXTENSIONS:
        return []
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return []
    total = 0
    evidence: list[str] = []
    for pattern, score, reason in SUSPICIOUS_SCRIPT_PATTERNS:
        if re.search(pattern, text):
            total += score
            evidence.append(reason)
    sample = text[:50_000]
    entropy = shannon_entropy(sample)
    if len(sample) > 500 and entropy > 5.2:
        total += 15
        evidence.append(f"High script entropy ({entropy:.2f}) suggesting possible obfuscation")
    if total < 25:
        return []
    score = min(total, 80)
    return [Detection(ObjectType.SCRIPT, str(path), score, severity_from_score(score), "; ".join(evidence),
                      "Review script content and origin. Quarantine only if untrusted.", sha256, "script_heuristics")]
