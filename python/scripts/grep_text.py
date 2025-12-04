from __future__ import annotations

import argparse
import re
from pathlib import Path
from typing import Iterable


def grep(pattern: str, path: Path) -> Iterable[str]:
    regex = re.compile(pattern)
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if regex.search(line):
            yield line


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Search for pattern in a file")
    parser.add_argument("pattern")
    parser.add_argument("file")
    args = parser.parse_args(argv)
    for match in grep(args.pattern, Path(args.file)):
        print(match)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

