from __future__ import annotations
import subprocess
from dataclasses import dataclass
from winseclite.utils.platform import is_windows


@dataclass(slots=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


class DefenderClient:
    """Safe Microsoft Defender integration. Never disables Defender."""

    def _run(self, command: str, timeout: int = 120) -> CommandResult:
        if not is_windows():
            return CommandResult(1, "", "Microsoft Defender cmdlets require Windows")
        proc = subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", command],
                              capture_output=True, text=True, encoding="utf-8", errors="ignore", timeout=timeout, check=False)
        return CommandResult(proc.returncode, proc.stdout, proc.stderr)

    def status(self) -> CommandResult:
        return self._run("Get-MpComputerStatus | ConvertTo-Json -Depth 3")

    def update_signatures(self) -> CommandResult:
        return self._run("Update-MpSignature", timeout=600)

    def quick_scan(self) -> CommandResult:
        return self._run("Start-MpScan -ScanType QuickScan", timeout=3600)

    def full_scan(self) -> CommandResult:
        return self._run("Start-MpScan -ScanType FullScan", timeout=24 * 3600)

    def threats(self) -> CommandResult:
        return self._run("Get-MpThreat | ConvertTo-Json -Depth 4")
