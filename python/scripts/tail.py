from __future__ import annotations

import argparse
from collections import deque
from pathlib import Path


def tail(path: Path, n: int = 10) -> list[str]:
    dq: deque[str] = deque(maxlen=n)
    with path.open(encoding="utf-8", errors="ignore") as file:
        for line in file:
            dq.append(line.rstrip("\n"))
    return list(dq)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Print the last N lines of a file")
    parser.add_argument("file")
    parser.add_argument("-n", type=int, default=10, help="number of lines")
    args = parser.parse_args(argv)
    for line in tail(Path(args.file), args.n):
        print(line)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

