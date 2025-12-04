from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


def file_hash(path: Path, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(8192), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Hash a file for cache-busting or verification")
    parser.add_argument("file")
    parser.add_argument("--algorithm", default="sha256")
    args = parser.parse_args(argv)
    print(file_hash(Path(args.file), args.algorithm))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

