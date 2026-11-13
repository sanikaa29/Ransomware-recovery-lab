"""Take consistent, locked backups of shopdb into the vault.

One backup =
  1. open a REPEATABLE READ transaction and export its snapshot;
  2. ``pg_dump --snapshot`` (inside the postgres container) sees exactly that snapshot;
  3. in the SAME transaction: per-table checksums, row counts, max order id, health;
  4. upload the dump, then a manifest, each with COMPLIANCE retention, then tag them.

Nothing is ever left unlocked: after each upload the retention is read back and a mismatch
raises, because the writer identity can delete unlocked versions.
"""

from __future__ import annotations

import signal
import subprocess
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import psycopg
from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console

from lab.config import LAB_DIR, LAST_CLEAN_PATH, ROOT, Settings
from lab.db import connect, max_order_id
from lab.health import HealthReport, check_database, load_baseline
from lab.manifest import (
    build_manifest,
    checksum_sql,
    dump_key,
    dumps_manifest,
    manifest_key,
    sha256_file,
)
from lab.retry import retry, seconds_until_next
from lab.schema import TABLES
from lab.storage import make_client
from lab.vault_rules import lock_problems, retention_until

TMP_DIR = LAB_DIR / "tmp"
MODE = "COMPLIANCE"
RETRIABLE = (OSError, psycopg.Error, ClientError, BotoCoreError)


class BackupError(RuntimeError):
    """A backup step failed in a way worth retrying or reporting."""


@dataclass(frozen=True)
class Snapshot:
    started_at: datetime
    row_counts: dict[str, int | None]
    checksums: dict[str, str]
    max_order_id: int | None
    health: HealthReport


@dataclass(frozen=True)
class BackupResult:
    key: str
    version_id: str
    size_bytes: int
    health: str
    reasons: tuple[str, ...]
    retain_until: datetime
    seconds: float


def run_pg_dump(settings: Settings, snapshot_id: str, dest: Path) -> None:
    """Custom-format dump of the snapshot. Runs inside the container, so no password travels."""
    command = [
        "docker", "compose", "exec", "-T", "postgres",
        "pg_dump", "-U", settings.pg_user, "-Fc", f"--snapshot={snapshot_id}", settings.pg_db,
    ]  # fmt: skip
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        with open(dest, "wb") as out:
            done = subprocess.run(
                command, cwd=ROOT, stdout=out, stderr=subprocess.PIPE, check=False
            )
    except FileNotFoundError:
        raise BackupError("docker not found") from None
    if done.returncode != 0:
        detail = done.stderr.decode("utf-8", "replace").strip()[:500]
        raise BackupError(f"pg_dump failed (exit {done.returncode}): {detail}")
    if dest.stat().st_size == 0:
        raise BackupError("pg_dump produced an empty file")


def take_snapshot(settings: Settings, dest: Path, baseline: dict[str, int] | None) -> Snapshot:
    """Dump plus every fact about the data, all from one transaction snapshot."""
    conn = connect(settings)
    try:
        conn.isolation_level = psycopg.IsolationLevel.REPEATABLE_READ
        conn.read_only = True
        started_at = datetime.now(UTC)
        snapshot_id = conn.execute("SELECT pg_export_snapshot()").fetchone()[0]
        run_pg_dump(settings, snapshot_id, dest)
        report = check_database(conn, baseline)
        counts = report.stats["row_counts"]
        checksums = {
            table: conn.execute(checksum_sql(table)).fetchone()[0]
            for table in TABLES
            if counts.get(table) is not None
        }
        newest = max_order_id(conn) if counts.get("orders") is not None else None
        return Snapshot(started_at, counts, checksums, newest, report)
    finally:
        conn.close()


def upload_locked(
    client: Any,
    bucket: str,
    key: str,
    body: bytes,
    retain_until: datetime,
    health: str,
) -> str:
    """Upload with COMPLIANCE retention, prove the lock is there, tag it. Returns the version id."""
    response = client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ObjectLockMode=MODE,
        ObjectLockRetainUntilDate=retain_until,
    )
    version_id = response.get("VersionId") or client.head_object(Bucket=bucket, Key=key).get(
        "VersionId"
    )
    if not version_id:
        raise BackupError(f"{key}: vault returned no version id (is versioning on?)")
    retention = client.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)
    problems = lock_problems(retention.get("Retention"), retain_until, MODE)
    if problems:
        raise BackupError(f"{key}: lock check failed: {'; '.join(problems)}")
    client.put_object_tagging(
        Bucket=bucket,
        Key=key,
        VersionId=version_id,
        Tagging={"TagSet": [{"Key": "health", "Value": health}]},
    )
    return str(version_id)


def _announce_retry(console: Console, what: str):  # noqa: ANN202
    def show(number: int, exc: BaseException, delay: float) -> None:
        first = (str(exc).strip().splitlines() or [type(exc).__name__])[0][:160]
        console.print(
            f"[yellow]{what} failed (attempt {number}): {first}. Retrying in {delay:.0f}s[/yellow]"
        )

    return show


def run_backup_once(settings: Settings, console: Console) -> BackupResult:
    """One full backup cycle with retries. Raises if it ultimately fails."""
    began = time.monotonic()
    client = make_client(settings, "writer")
    baseline = load_baseline(LAST_CLEAN_PATH) if LAST_CLEAN_PATH.is_file() else None
    TMP_DIR.mkdir(parents=True, exist_ok=True)
    scratch = TMP_DIR / "current.dump"
    try:
        snapshot = retry(
            lambda: take_snapshot(settings, scratch, baseline),
            catch=(BackupError, *RETRIABLE),
            on_retry=_announce_retry(console, "snapshot/dump"),
        )
        key = dump_key(snapshot.started_at)
        sha = sha256_file(scratch)
        size = scratch.stat().st_size
        data = scratch.read_bytes()
    finally:
        scratch.unlink(missing_ok=True)
    health = snapshot.health.status
    retain_until = retention_until(datetime.now(UTC), settings.retention_minutes)
    version_id = retry(
        lambda: upload_locked(client, settings.s3_bucket, key, data, retain_until, health),
        catch=(BackupError, *RETRIABLE),
        on_retry=_announce_retry(console, "dump upload"),
    )
    manifest = build_manifest(
        key=key,
        version_id=version_id,
        started_at=snapshot.started_at,
        completed_at=datetime.now(UTC),
        sha256=sha,
        size_bytes=size,
        row_counts=snapshot.row_counts,
        checksums=snapshot.checksums,
        max_order_id=snapshot.max_order_id,
        health_status=health,
        health_reasons=snapshot.health.reasons,
        retain_until=retain_until,
    )
    body = dumps_manifest(manifest)
    retry(
        lambda: upload_locked(
            client, settings.s3_bucket, manifest_key(key), body, retain_until, health
        ),
        catch=(BackupError, *RETRIABLE),
        on_retry=_announce_retry(console, "manifest upload"),
    )
    if health == "clean":
        LAST_CLEAN_PATH.parent.mkdir(parents=True, exist_ok=True)
        LAST_CLEAN_PATH.write_bytes(body)
    return BackupResult(
        key, version_id, size, health, snapshot.health.reasons, retain_until,
        time.monotonic() - began,
    )  # fmt: skip


def print_result(result: BackupResult, console: Console) -> None:
    colour = "green" if result.health == "clean" else "bold red"
    console.print(
        f"[{colour}]BACKUP {result.health.upper()}[/{colour}] {result.key} "
        f"{result.size_bytes / 1024:.0f} KiB, locked until "
        f"{result.retain_until:%H:%M:%S}Z, took {result.seconds:.1f}s"
    )
    for reason in result.reasons:
        console.print(f"  [red]- {reason}[/red]")


def run_loop(settings: Settings, console: Console) -> int:
    """Back up every ``backup_interval_seconds`` until Ctrl+C. A failed cycle is reported
    loudly and the loop carries on: the attack must not be able to stop the backups."""
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    interval = settings.backup_interval_seconds
    console.print(f"Backing up every {interval}s. Ctrl+C to stop.")
    failures = 0
    while not stop.is_set():
        started = time.monotonic()
        try:
            print_result(run_backup_once(settings, console), console)
        except Exception as exc:  # noqa: BLE001 - the loop must survive anything
            failures += 1
            first = (str(exc).strip().splitlines() or [type(exc).__name__])[0][:300]
            console.print(f"[bold red]BACKUP FAILED[/bold red] ({type(exc).__name__}) {first}")
        stop.wait(seconds_until_next(interval, time.monotonic() - started))
    console.print(f"Backup loop stopped ({failures} failed cycle(s)).")
    return 0
