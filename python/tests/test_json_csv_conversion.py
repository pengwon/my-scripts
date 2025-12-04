from __future__ import annotations

import csv
import json
from pathlib import Path

from scripts.csv_to_json import convert as csv_to_json
from scripts.json_to_csv import convert as json_to_csv


def test_json_to_csv_round_trip(tmp_path: Path) -> None:
    data = [
        {"name": "alice", "age": 30},
        {"name": "bob", "age": 25, "city": "NYC"},
    ]
    json_path = tmp_path / "data.json"
    csv_path = tmp_path / "data.csv"
    json_path.write_text(json.dumps(data), encoding="utf-8")

    json_to_csv(json_path, csv_path)

    with csv_path.open(newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)
    assert rows[0] == ["age", "city", "name"]
    assert rows[1] == ["30", "", "alice"]
    assert rows[2] == ["25", "NYC", "bob"]


def test_csv_to_json(tmp_path: Path) -> None:
    csv_path = tmp_path / "input.csv"
    csv_path.write_text("name,age\nalice,30\nbob,25\n", encoding="utf-8")
    json_path = tmp_path / "output.json"

    csv_to_json(csv_path, json_path)

    data = json.loads(json_path.read_text(encoding="utf-8"))
    assert data == [
        {"name": "alice", "age": "30"},
        {"name": "bob", "age": "25"},
    ]

