from __future__ import annotations
from dataclasses import dataclass
from winseclite.core.models import Detection, ObjectType
from winseclite.core.risk_score import severity_from_score
from winseclite.utils.platform import is_windows


@dataclass(frozen=True)
class RegistryLocation:
    hive_name: str
    subkey: str


class RegistryScanner:
    """Read-only registry persistence scanner."""
    LOCATIONS = [
        RegistryLocation("HKCU", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        RegistryLocation("HKCU", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
        RegistryLocation("HKLM", r"Software\Microsoft\Windows\CurrentVersion\Run"),
        RegistryLocation("HKLM", r"Software\Microsoft\Windows\CurrentVersion\RunOnce"),
    ]

    def scan(self) -> list[Detection]:
        if not is_windows():
            return []
        import winreg  # type: ignore
        hives = {"HKCU": winreg.HKEY_CURRENT_USER, "HKLM": winreg.HKEY_LOCAL_MACHINE}
        detections: list[Detection] = []
        for loc in self.LOCATIONS:
            try:
                with winreg.OpenKey(hives[loc.hive_name], loc.subkey) as key:
                    for i in range(winreg.QueryInfoKey(key)[1]):
                        try:
                            name, value, _ = winreg.EnumValue(key, i)
                        except OSError:
                            continue
                        score, evidence = self._score_value(str(value))
                        if score >= 25:
                            detections.append(Detection(ObjectType.REGISTRY, f"{loc.hive_name}\\{loc.subkey}\\{name}", score,
                                                        severity_from_score(score), evidence,
                                                        "Verify owner. Disable manually only after validation.",
                                                        rule_name="registry_startup_heuristics", metadata={"value": str(value)}))
            except OSError:
                continue
        return detections

    @staticmethod
    def _score_value(value: str) -> tuple[int, str]:
        lower = value.lower()
        score = 0
        evidence: list[str] = []
        if any(x in lower for x in ["\\temp\\", "%temp%", "appdata\\local\\temp", "downloads"]):
            score += 30; evidence.append("Startup command points to user-writable or temporary location")
        if any(x in lower for x in ["powershell", "wscript", "cscript", "mshta", "cmd.exe /c"]):
            score += 25; evidence.append("Startup command uses script interpreter or shell")
        if "-enc" in lower or "encodedcommand" in lower:
            score += 35; evidence.append("Startup command includes encoded PowerShell indicator")
        return min(score, 90), "; ".join(evidence) or "Suspicious registry startup entry"
