from __future__ import annotations

from pathlib import Path

from scripts.dir_size import dir_size


def test_dir_size(tmp_path: Path) -> None:
    (tmp_path / "a.txt").write_bytes(b"abc")
    nested = tmp_path / "nested"
    nested.mkdir()
    (nested / "b.bin").write_bytes(b"12345")
    assert dir_size(tmp_path) == 8

