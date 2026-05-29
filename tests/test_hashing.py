from pathlib import Path
from winseclite.utils.hashing import sha256_file


def test_sha256_file(tmp_path: Path) -> None:
    p = tmp_path / "sample.txt"
    p.write_text("hello", encoding="utf-8")
    assert sha256_file(p) == "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
