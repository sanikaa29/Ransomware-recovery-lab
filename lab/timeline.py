"""``.lab/timeline.json``: the moments the report is computed from (stdlib only).

Keys: attack_start, attack_end, incident_detected, restore_start, restore_verified (UTC ISO
strings) and max_order_id_at_attack_start (int). Later phases add their keys to the same file.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from lab.config import LAB_DIR
from lab.manifest import iso_z, parse_iso

TIMELINE_PATH = LAB_DIR / "timeline.json"
TIME_KEYS = (
    "attack_start",
    "attack_end",
    "incident_detected",
    "restore_start",
    "restore_verified",
)


def read(path: Path = TIMELINE_PATH) -> dict[str, Any]:
    if not path.is_file():
        return {}
    data = json.loads(path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def write(data: dict[str, Any], path: Path = TIMELINE_PATH) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    tmp.replace(path)


def reset(path: Path = TIMELINE_PATH) -> None:
    """A new incident starts a new timeline."""
    write({}, path)


def record(key: str, moment: datetime, path: Path = TIMELINE_PATH) -> None:
    if key not in TIME_KEYS:
        raise ValueError(f"unknown timeline key {key!r}")
    data = read(path)
    data[key] = iso_z(moment)
    write(data, path)


def set_value(key: str, value: Any, path: Path = TIMELINE_PATH) -> None:
    data = read(path)
    data[key] = value
    write(data, path)


def moment(data: dict[str, Any], key: str) -> datetime | None:
    value = data.get(key)
    return parse_iso(value) if isinstance(value, str) else None
