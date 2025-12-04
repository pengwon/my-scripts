from __future__ import annotations

import argparse
import csv
import json
from pathlib import Path
from typing import Any, Iterable, Mapping


def rows_from_json(records: Iterable[Mapping[str, Any]]) -> tuple[list[str], list[list[Any]]]:
    records = list(records)
    if not records:
        return [], []
    headers = sorted({key for record in records for key in record})
    rows = [[record.get(header, "") for header in headers] for record in records]
    return headers, rows


def convert(input_path: Path, output_path: Path) -> None:
    data = json.loads(input_path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        raise ValueError("Expected a JSON array of objects")
    headers, rows = rows_from_json(data)
    with output_path.open("w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(headers)
        writer.writerows(rows)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Convert JSON array of objects to CSV")
    parser.add_argument("input")
    parser.add_argument("output")
    args = parser.parse_args(argv)
    convert(Path(args.input), Path(args.output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

