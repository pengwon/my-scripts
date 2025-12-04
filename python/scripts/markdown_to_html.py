from __future__ import annotations

import argparse
import html
import re
from pathlib import Path


def md_to_html(md: str) -> str:
    """Very small markdown subset converter (headings, bold, italics)."""
    lines = md.splitlines()
    html_lines: list[str] = []
    for line in lines:
        if line.startswith("# "):
            html_lines.append(f"<h1>{html.escape(line[2:])}</h1>")
            continue
        if line.startswith("## "):
            html_lines.append(f"<h2>{html.escape(line[3:])}</h2>")
            continue
        text = re.sub(r"\*\*(.+?)\*\*", lambda m: f"<strong>{html.escape(m.group(1))}</strong>", line)
        text = re.sub(r"\*(.+?)\*", lambda m: f"<em>{html.escape(m.group(1))}</em>", text)
        html_lines.append(f"<p>{html.escape(text)}</p>")
    return "\n".join(html_lines)


def convert(input_path: Path, output_path: Path) -> None:
    output_path.write_text(md_to_html(input_path.read_text(encoding="utf-8")), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert a tiny markdown subset to HTML")
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    convert(Path(args.input), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

