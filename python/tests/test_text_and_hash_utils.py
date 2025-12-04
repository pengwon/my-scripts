from __future__ import annotations

from pathlib import Path

from scripts.file_hash import file_hash
from scripts.grep_text import grep
from scripts.markdown_to_html import md_to_html
from scripts.tail import tail


def test_grep_text(tmp_path: Path) -> None:
    path = tmp_path / "sample.txt"
    path.write_text("first line\nsecond match\nthird\nmatch again\n", encoding="utf-8")
    assert list(grep("match", path)) == ["second match", "match again"]


def test_md_to_html() -> None:
    md = "# Title\n## Subtitle\nhello **world** and *italic*\n"
    html = md_to_html(md)
    assert "<h1>Title</h1>" in html
    assert "<h2>Subtitle</h2>" in html
    assert "<strong>world</strong>" in html
    assert "<em>italic</em>" in html


def test_file_hash(tmp_path: Path) -> None:
    path = tmp_path / "data.bin"
    path.write_bytes(b"abc")
    assert file_hash(path, "md5") == "900150983cd24fb0d6963f7d28e17f72"


def test_tail(tmp_path: Path) -> None:
    path = tmp_path / "log.txt"
    lines = [f"line {i}" for i in range(20)]
    path.write_text("\n".join(lines), encoding="utf-8")
    assert tail(path, 3) == ["line 17", "line 18", "line 19"]

