"""Which backup to restore, and how to fall back (pure: no database, no vault).

Rules, in order, for every backup newest first:
  * the manifest must be readable (it is the part the attacker cannot rewrite);
  * ``--before`` keeps only backups whose dump started strictly before that moment;
  * a backup is skipped if its tag OR its manifest says suspect. The tag can be changed by
    anyone with write access, so a "clean" tag never overrides a suspect manifest.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime
from typing import Any, TypeVar

from lab.catalog import CatalogEntry, newest_first

R = TypeVar("R")
_DB_NAME = re.compile(r"^[a-z_][a-z0-9_]*$")


class RestoreRejected(Exception):  # noqa: N818 - reads better than RestoreRejectedError
    """One candidate failed verification; the next older one should be tried."""


Skipped = tuple[CatalogEntry, str]


def partition_candidates(
    entries: list[CatalogEntry], before: datetime | None = None
) -> tuple[list[CatalogEntry], list[Skipped]]:
    """(candidates newest first, [(entry, reason) skipped])."""
    candidates: list[CatalogEntry] = []
    skipped: list[Skipped] = []
    for entry in newest_first(entries):
        manifest = entry.manifest
        if manifest is None:
            skipped.append((entry, f"manifest unreadable ({entry.problem or 'unknown'})"))
        elif not manifest.get("dump_version_id"):
            skipped.append((entry, "manifest has no dump version id"))
        elif before is not None and not (entry.started and entry.started < before):
            skipped.append((entry, "started at or after --before"))
        elif entry.tag == "suspect":
            skipped.append((entry, _suspect_reason("tagged suspect", manifest)))
        elif manifest["health"]["status"] == "suspect":
            skipped.append((entry, _suspect_reason("manifest says suspect", manifest)))
        else:
            candidates.append(entry)
    return candidates, skipped


def _suspect_reason(prefix: str, manifest: dict[str, Any]) -> str:
    reasons = manifest["health"].get("reasons") or []
    return f"{prefix}: {reasons[0]}" if reasons else prefix


def restore_first_good(
    candidates: list[CatalogEntry], attempt: Callable[[CatalogEntry], R]
) -> tuple[tuple[CatalogEntry, R] | None, list[Skipped]]:
    """Try candidates in order. ``attempt`` raises ``RestoreRejected`` to reject one.

    Returns ((entry, result) or None, rejections).
    """
    rejected: list[Skipped] = []
    for entry in candidates:
        try:
            return (entry, attempt(entry)), rejected
        except RestoreRejected as exc:
            rejected.append((entry, str(exc)))
    return None, rejected


def compare_to_manifest(
    manifest: dict[str, Any], counts: dict[str, int | None], checksums: dict[str, str]
) -> list[str]:
    """Differences between the restored database and what the backup recorded."""
    problems = []
    for table, expected in sorted(manifest["row_counts"].items()):
        actual = counts.get(table)
        if actual != expected:
            problems.append(f"{table}: {actual} rows restored, backup recorded {expected}")
    for table, expected in sorted(manifest["checksums"].items()):
        if checksums.get(table) != expected:
            problems.append(f"{table}: checksum differs from the backup's")
    return problems


def check_restore_target(restore_db: str, restore_port: int, prod_db: str, prod_port: int) -> None:
    """The restore drops and recreates its database, so it must never be production."""
    if restore_db == prod_db:
        raise RestoreRejected(f"restore database {restore_db!r} is the production database")
    if restore_port == prod_port:
        raise RestoreRejected("restore port is the production port")
    if not _DB_NAME.match(restore_db):
        raise RestoreRejected(f"restore database name {restore_db!r} is not a plain identifier")
