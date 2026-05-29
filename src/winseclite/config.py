from __future__ import annotations

import os
from pathlib import Path
from typing import Literal
from pydantic import BaseModel, Field

ScanMode = Literal["quick", "full", "custom"]


class AppConfig(BaseModel):
    """Application configuration with conservative defaults."""

    app_name: str = "WinSecLite"
    base_dir: Path = Field(default_factory=lambda: Path.cwd())
    data_dir: Path = Field(default_factory=lambda: Path.cwd() / "data")
    db_path: Path = Field(default_factory=lambda: Path.cwd() / "data" / "app.db")
    rules_dir: Path = Field(default_factory=lambda: Path.cwd() / "rules")
    yara_dir: Path = Field(default_factory=lambda: Path.cwd() / "rules" / "yara")
    hashes_dir: Path = Field(default_factory=lambda: Path.cwd() / "rules" / "hashes")
    report_dir: Path = Field(default_factory=lambda: Path.cwd() / "reports")
    quarantine_dir: Path = Field(default_factory=lambda: Path.cwd() / "data" / "quarantine")
    log_dir: Path = Field(default_factory=lambda: Path.cwd() / "logs")
    max_file_size_mb: int = 200
    max_workers: int = 4
    follow_symlinks: bool = False
    enable_yara: bool = True
    default_quarantine: bool = False

    @property
    def max_file_size_bytes(self) -> int:
        return self.max_file_size_mb * 1024 * 1024

    def ensure_dirs(self) -> None:
        for path in [self.data_dir, self.report_dir, self.quarantine_dir, self.log_dir]:
            path.mkdir(parents=True, exist_ok=True)


def load_config() -> AppConfig:
    cwd = Path(os.environ.get("WINSECLITE_HOME", Path.cwd())).resolve()
    cfg = AppConfig(
        base_dir=cwd,
        data_dir=cwd / "data",
        db_path=cwd / "data" / "app.db",
        rules_dir=cwd / "rules",
        yara_dir=cwd / "rules" / "yara",
        hashes_dir=cwd / "rules" / "hashes",
        report_dir=cwd / "reports",
        quarantine_dir=cwd / "data" / "quarantine",
        log_dir=cwd / "logs",
    )
    cfg.ensure_dirs()
    return cfg
