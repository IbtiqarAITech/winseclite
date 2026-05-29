from __future__ import annotations
import os
from pathlib import Path


def existing_paths(paths: list[Path]) -> list[Path]:
    return [p for p in paths if p.exists()]


def quick_scan_paths() -> list[Path]:
    user = Path.home()
    temp = Path(os.environ.get("TEMP", str(user / "AppData" / "Local" / "Temp")))
    appdata = Path(os.environ.get("APPDATA", str(user / "AppData" / "Roaming")))
    localappdata = Path(os.environ.get("LOCALAPPDATA", str(user / "AppData" / "Local")))
    programdata = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
    return existing_paths([
        user / "Downloads",
        user / "Desktop",
        user / "Documents",
        temp,
        appdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        programdata / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup",
        localappdata / "Temp",
    ])
