"""Restore the newest trustworthy backup into the clean-room database.

Steps per candidate (newest first, skipping suspect ones): download the exact version named in
the manifest, check its SHA-256, drop and recreate ``shopdb_restored``, ``pg_restore`` into it,
then prove it: health clean, row counts and per-table checksums equal to the backup's manifest.
Any failure falls back to the next older candidate. Production is never touched.
"""

from __future__ import annotations

import hashlib
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from lab import timeline
from lab.backup import TMP_DIR
from lab.catalog import CatalogEntry, list_backups
from lab.config import ROOT, Settings
from lab.db import connect, max_order_id
from lab.health import HealthReport, check_database
from lab.manifest import checksum_sql
from lab.restore_plan import (
    RestoreRejected,
    check_restore_target,
    compare_to_manifest,
    partition_candidates,
    restore_first_good,
)
from lab.schema import TABLES
from lab.storage import make_client

CHUNK = 1024 * 1024


@dataclass(frozen=True)
class Restored:
    max_order_id: int | None
    health: HealthReport
    rows: int


def download_verified(client: Any, bucket: str, manifest: dict[str, Any], dest: Path) -> None:
    """Fetch the exact version the manifest names; reject it unless its SHA-256 matches."""
    digest = hashlib.sha256()
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        body = client.get_object(
            Bucket=bucket, Key=manifest["dump_key"], VersionId=manifest["dump_version_id"]
        )["Body"]
        with open(dest, "wb") as out:
            while chunk := body.read(CHUNK):
                digest.update(chunk)
                out.write(chunk)
    except (BotoCoreError, ClientError) as exc:
        raise RestoreRejected(f"cannot download dump: {type(exc).__name__}") from None
    if digest.hexdigest() != manifest["sha256"]:
        raise RestoreRejected("SHA-256 of the downloaded dump does not match the manifest")


def recreate_restore_db(settings: Settings) -> None:
    check_restore_target(
        settings.restore_pg_db, settings.restore_pg_port, settings.pg_db, settings.pg_port
    )
    name = settings.restore_pg_db  # validated as a plain identifier above
    with connect(settings, restore=True, dbname="postgres", autocommit=True) as conn:
        conn.execute(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)')
        conn.execute(f'CREATE DATABASE "{name}"')


def run_pg_restore(settings: Settings, dump: Path) -> None:
    command = [
        "docker", "compose", "exec", "-T", "postgres_restore",
        "pg_restore", "-U", settings.pg_user, "-d", settings.restore_pg_db,
        "--clean", "--if-exists", "--no-owner",
    ]  # fmt: skip
    try:
        with open(dump, "rb") as handle:
            done = subprocess.run(command, cwd=ROOT, stdin=handle, capture_output=True, check=False)
    except FileNotFoundError:
        raise RestoreRejected("docker not found") from None
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()[:400]
        raise RestoreRejected(f"pg_restore failed (exit {done.returncode}): {detail}")


def verify_restored(settings: Settings, manifest: dict[str, Any]) -> Restored:
    """Health plus an exact comparison with the manifest; raises RestoreRejected on any gap."""
    with connect(settings, restore=True) as conn:
        report = check_database(conn, manifest["row_counts"])
        counts = report.stats["row_counts"]
        checksums = {
            t: conn.execute(checksum_sql(t)).fetchone()[0]
            for t in TABLES
            if counts.get(t) is not None
        }
        newest = max_order_id(conn) if counts.get("orders") is not None else None
    if not report.is_clean:
        raise RestoreRejected("restored database is suspect: " + "; ".join(report.reasons))
    problems = compare_to_manifest(manifest, counts, checksums)
    if problems:
        raise RestoreRejected("does not match the backup's manifest: " + "; ".join(problems))
    return Restored(newest, report, sum(n or 0 for n in counts.values()))


def restore_entry(settings: Settings, client: Any, entry: CatalogEntry) -> Restored:
    manifest = entry.manifest or {}
    scratch = TMP_DIR / "restore.dump"
    try:
        download_verified(client, settings.s3_bucket, manifest, scratch)
        recreate_restore_db(settings)
        run_pg_restore(settings, scratch)
    finally:
        scratch.unlink(missing_ok=True)
    return verify_restored(settings, manifest)


def _print_choices(skipped: list[tuple[CatalogEntry, str]], console: Any, title: str) -> None:
    from rich.table import Table

    if not skipped:
        return
    table = Table(title=title)
    table.add_column("Backup started (UTC)")
    table.add_column("Why not used")
    for entry, reason in skipped:
        when = f"{entry.started:%H:%M:%S}" if entry.started else entry.manifest_key.rsplit("/")[-1]
        table.add_row(when, f"[yellow]{reason}[/yellow]")
    console.print(table)


def run_restore(settings: Settings, console: Any, *, before: datetime | None = None) -> int:
    """Exit code 0 when a backup was restored and verified, 1 otherwise."""
    timeline.record("restore_start", datetime.now(UTC))
    client = make_client(settings, "writer")
    try:
        entries = list_backups(client, settings.s3_bucket)
    except (BotoCoreError, ClientError) as exc:
        console.print(f"[red]Cannot list the vault: {type(exc).__name__}: {exc}[/red]")
        return 1
    candidates, skipped = partition_candidates(entries, before)
    console.print(f"{len(entries)} backups in the vault, {len(candidates)} eligible.")
    _print_choices(skipped, console, "Skipped (never restored)")
    found, rejected = restore_first_good(
        candidates, lambda entry: _announce_and_restore(settings, client, entry, console)
    )
    _print_choices(rejected, console, "Rejected during restore (fell back to an older one)")
    if found is None:
        console.print("[bold red]RESTORE FAILED[/bold red] no eligible backup could be verified.")
        return 1
    entry, restored = found
    timeline.record("restore_verified", datetime.now(UTC))
    timeline.set_value("restored_dump_started_at", (entry.manifest or {})["dump_started_at"])
    timeline.set_value("restored_backup_key", (entry.manifest or {})["dump_key"])
    timeline.set_value("restored_max_order_id", restored.max_order_id)
    console.print(
        f"[bold green]RESTORE VERIFIED[/bold green] from backup started "
        f"{entry.started:%Y-%m-%d %H:%M:%S}Z into {settings.restore_pg_db} "
        f"(port {settings.restore_pg_port})"
    )
    console.print(
        f"  sha256 ok, health clean, {restored.rows:,} rows and all table checksums match; "
        f"newest order id {restored.max_order_id}"
    )
    return 0


def _announce_and_restore(
    settings: Settings, client: Any, entry: CatalogEntry, console: Any
) -> Restored:
    console.print(f"Trying backup started {entry.started:%H:%M:%S}Z ...")
    return restore_entry(settings, client, entry)
