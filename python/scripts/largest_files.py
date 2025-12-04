from __future__ import annotations

import argparse
import heapq
from pathlib import Path
from typing import Iterable


def largest_files(path: Path, count: int = 5) -> list[tuple[int, Path]]:
    files: list[tuple[int, Path]] = []
    for entry in path.rglob("*"):
        if entry.is_file():
            try:
                files.append((entry.stat().st_size, entry))
            except OSError:
                continue
    return heapq.nlargest(count, files, key=lambda item: item[0])


def _format_entry(entry: tuple[int, Path]) -> str:
    size, path = entry
    return f"{size}\t{path}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="List largest files under a path")
    parser.add_argument("path", nargs="?", default=".")
    parser.add_argument("-n", "--count", type=int, default=5, help="number of files")
    args = parser.parse_args(argv)
    for item in largest_files(Path(args.path), args.count):
        print(_format_entry(item))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

