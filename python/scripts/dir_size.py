from __future__ import annotations

import os
from pathlib import Path


def dir_size(path: Path) -> int:
    """Return total size of all files under path (bytes)."""
    total = 0
    for root, _, files in os.walk(path):
        for name in files:
            try:
                total += (Path(root) / name).stat().st_size
            except OSError:
                continue  # ignore unreadable entries
    return total


def main(argv: list[str] | None = None) -> int:
    target = Path(argv[0]) if argv else Path(".")
    print(dir_size(target))
    return 0


if __name__ == "__main__":
    import sys

    raise SystemExit(main(sys.argv[1:]))

