from __future__ import annotations
from pathlib import Path


class HashMatcher:
    """Match SHA256 hashes from text files."""

    def __init__(self, known_bad: set[str] | None = None, known_good: set[str] | None = None) -> None:
        self.known_bad = {h.lower() for h in known_bad or set()}
        self.known_good = {h.lower() for h in known_good or set()}

    @staticmethod
    def load_hash_file(path: Path) -> set[str]:
        if not path.exists():
            return set()
        hashes: set[str] = set()
        for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            value = line.strip().lower()
            if not value or value.startswith("#"):
                continue
            if len(value) == 64 and all(c in "0123456789abcdef" for c in value):
                hashes.add(value)
        return hashes

    @classmethod
    def from_directory(cls, hashes_dir: Path) -> "HashMatcher":
        return cls(
            known_bad=cls.load_hash_file(hashes_dir / "known_bad_hashes.txt"),
            known_good=cls.load_hash_file(hashes_dir / "known_good_hashes.txt"),
        )

    def is_known_bad(self, sha256: str) -> bool:
        return sha256.lower() in self.known_bad

    def is_known_good(self, sha256: str) -> bool:
        return sha256.lower() in self.known_good
