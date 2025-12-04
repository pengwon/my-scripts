from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path


def convert(input_path: Path, output_path: Path) -> None:
    with input_path.open(newline="", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        data = list(reader)
    output_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert CSV to JSON array")
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    convert(Path(args.input), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

