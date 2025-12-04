from __future__ import annotations

from pathlib import Path

from scripts.largest_files import largest_files


def test_largest_files(tmp_path: Path) -> None:
    files = {
        "small.txt": b"1",
        "medium.txt": b"12345",
        "big.txt": b"1234567890",
    }
    for name, data in files.items():
        (tmp_path / name).write_bytes(data)
    top = largest_files(tmp_path, 2)
    assert [path.name for _, path in top] == ["big.txt", "medium.txt"]

