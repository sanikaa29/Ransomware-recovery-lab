"""Backup naming and manifests (stdlib only: pure and unit-testable).

A backup is two objects: ``backups/YYYY/MM/DD/backup-<UTC>.dump`` and a sibling
``.manifest.json`` that describes it. The manifest is what restore trusts.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from lab.schema import TABLES

MANIFEST_VERSION = 1
KEY_PREFIX = "backups"
STAMP_FORMAT = "%Y%m%dT%H%M%SZ"
CHUNK = 1024 * 1024
REQUIRED_FIELDS = (
    "manifest_version",
    "dump_key",
    "dump_version_id",
    "dump_started_at",
    "completed_at",
    "sha256",
    "size_bytes",
    "row_counts",
    "checksums",
    "max_order_id",
    "health",
    "retain_until",
)


def sha256_file(path: str | Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        while chunk := handle.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def iso_z(moment: datetime) -> str:
    """UTC ISO-8601 with microseconds and a trailing Z, e.g. 2026-11-12T23:01:02.123456Z."""
    if moment.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def parse_iso(text: str) -> datetime:
    """Parse what ``iso_z`` writes (also accepts +00:00 and no fraction)."""
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"timestamp {text!r} has no timezone")
    return parsed.astimezone(UTC)


def dump_key(started: datetime) -> str:
    """``backups/YYYY/MM/DD/backup-<UTC timestamp>.dump`` (date folders in UTC)."""
    utc = started.astimezone(UTC)
    return f"{KEY_PREFIX}/{utc:%Y/%m/%d}/backup-{utc.strftime(STAMP_FORMAT)}.dump"


def manifest_key(key: str) -> str:
    if not key.endswith(".dump"):
        raise ValueError(f"not a dump key: {key!r}")
    return key.removesuffix(".dump") + ".manifest.json"


def checksum_sql(table: str) -> str:
    """Per-table fingerprint, computed inside the backup's snapshot.

    ``t::text`` is the row's text form; ordering by id makes it deterministic.
    """
    if table not in TABLES:
        raise ValueError(f"unknown table {table!r}")
    return f"SELECT md5(coalesce(string_agg(t::text, '|' ORDER BY id), '')) FROM {table} t"


def build_manifest(
    *,
    key: str,
    version_id: str | None,
    started_at: datetime,
    completed_at: datetime,
    sha256: str,
    size_bytes: int,
    row_counts: dict[str, int | None],
    checksums: dict[str, str],
    max_order_id: int | None,
    health_status: str,
    health_reasons: list[str] | tuple[str, ...],
    retain_until: datetime,
    mode: str = "COMPLIANCE",
) -> dict[str, Any]:
    return {
        "manifest_version": MANIFEST_VERSION,
        "dump_key": key,
        "dump_version_id": version_id,
        "dump_started_at": iso_z(started_at),
        "completed_at": iso_z(completed_at),
        "sha256": sha256,
        "size_bytes": size_bytes,
        "row_counts": dict(row_counts),
        "checksums": dict(checksums),
        "max_order_id": max_order_id,
        "health": {"status": health_status, "reasons": list(health_reasons)},
        "retain_until": iso_z(retain_until),
        "retention_mode": mode,
    }


def dumps_manifest(manifest: dict[str, Any]) -> bytes:
    """Stable bytes: sorted keys, so the same manifest always serialises the same way."""
    return (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")


def parse_manifest(data: bytes | str) -> dict[str, Any]:
    """Load and sanity-check a manifest. Raises ValueError with a clear reason."""
    try:
        manifest = json.loads(data)
    except json.JSONDecodeError as exc:
        raise ValueError(f"manifest is not valid JSON: {exc}") from None
    if not isinstance(manifest, dict):
        raise ValueError("manifest must be a JSON object")
    missing = [name for name in REQUIRED_FIELDS if name not in manifest]
    if missing:
        raise ValueError(f"manifest is missing: {', '.join(missing)}")
    health = manifest["health"]
    if not isinstance(health, dict) or health.get("status") not in ("clean", "suspect"):
        raise ValueError("manifest health.status must be 'clean' or 'suspect'")
    return manifest
