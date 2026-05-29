# WinSecLite

WinSecLite is a defensive Windows security utility / lightweight endpoint hygiene scanner.
It complements Microsoft Defender by scanning risky locations, suspicious scripts, startup entries,
registry persistence locations, scheduled tasks, services, processes, and network connections.

> Defensive-only: no exploitation, stealth, credential access, ransomware behavior, malware persistence,
evasion, packet sniffing, or destructive automatic remediation.

## Implemented in this scaffold

- CLI scanner with Typer
- SQLite logging database
- SHA256 hashing
- Known-bad / known-good hash matching
- Script heuristic detection
- Optional YARA matching
- File scanner
- Process scanner
- Registry startup scanner
- Scheduled task scanner
- Service scanner
- Network scanner
- Quarantine manager
- HTML/JSON reports
- Microsoft Defender PowerShell integration
- Windows Task Scheduler helper script
- PyInstaller build script
- Minimal PySide6 GUI skeleton
- Codex continuation prompt and repo instructions

## Requirements

- Windows 10 or Windows 11
- Python 3.12+
- PowerShell 5.1+ or PowerShell 7+
- Administrator rights for complete HKLM/services/system scheduled task visibility

## Quick start

```powershell
cd winseclite
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
$env:PYTHONPATH = "$PWD\src"
python -m winseclite.cli init-db
python -m winseclite.cli doctor
python -m winseclite.cli scan quick --report html
```

## Build EXE

```powershell
.\scripts\build_exe.ps1
```

## Create a daily scheduled scan

```powershell
.\scripts\create_scheduled_scan.ps1 -InstallPath "C:\Program Files\WinSecLite" -Time "09:00"
```

## CLI examples

```powershell
python -m winseclite.cli scan quick
python -m winseclite.cli scan path "$env:USERPROFILE\Downloads" --report html
python -m winseclite.cli defender status
python -m winseclite.cli defender quick-scan
python -m winseclite.cli quarantine list
```

## Safety testing

Use only safe artifacts such as benign scripts and the EICAR anti-malware test file in a VM or controlled folder.
Do not test with live malware on your main machine.
