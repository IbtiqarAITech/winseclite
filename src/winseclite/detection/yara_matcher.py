from __future__ import annotations
import logging
from pathlib import Path
from typing import Any
logger = logging.getLogger(__name__)


class YaraMatcher:
    """Optional YARA matcher. Rules must be curated to reduce false positives."""

    def __init__(self, rules_dir: Path, enabled: bool = True) -> None:
        self.rules_dir = rules_dir
        self.enabled = enabled
        self._rules: Any | None = None
        self._load()

    def _load(self) -> None:
        if not self.enabled:
            return
        try:
            import yara  # type: ignore
        except Exception as exc:
            logger.warning("YARA unavailable: %s", exc)
            return
        if not self.rules_dir.exists():
            return
        rule_files = {p.stem: str(p) for p in self.rules_dir.glob("*.yar")}
        if not rule_files:
            return
        try:
            self._rules = yara.compile(filepaths=rule_files)
        except Exception as exc:
            logger.error("Failed to compile YARA rules: %s", exc)

    def match_file(self, path: Path, timeout_seconds: int = 10) -> list[str]:
        if self._rules is None:
            return []
        try:
            return [m.rule for m in self._rules.match(str(path), timeout=timeout_seconds)]
        except Exception as exc:
            logger.debug("YARA scan failed for %s: %s", path, exc)
            return []
