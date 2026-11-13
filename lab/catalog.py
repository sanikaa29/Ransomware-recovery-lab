"""List the backups in the vault, newest first (read-only). Restore reuses this in Phase 6."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any

from lab.manifest import parse_iso, parse_manifest

MANIFEST_SUFFIX = ".manifest.json"


@dataclass(frozen=True)
class CatalogEntry:
    manifest_key: str
    manifest_version_id: str
    manifest: dict[str, Any] | None  # None when the manifest is unreadable
    tag: str | None  # the health tag on the manifest object
    lock_mode: str | None
    lock_until: datetime | None
    problem: str = ""

    @property
    def started(self) -> datetime | None:
        return parse_iso(self.manifest["dump_started_at"]) if self.manifest else None


def newest_first(entries: list[CatalogEntry]) -> list[CatalogEntry]:
    """Newest dump first; unreadable manifests go last, ordered by key (which has a timestamp)."""
    readable = [e for e in entries if e.started is not None]
    broken = [e for e in entries if e.started is None]
    readable.sort(key=lambda e: e.started, reverse=True)
    broken.sort(key=lambda e: e.manifest_key, reverse=True)
    return readable + broken


def locked_targets(
    entries: list[CatalogEntry], now: datetime, limit: int = 20
) -> list[CatalogEntry]:
    """Readable backups whose lock is still running, newest first. These are the ones the
    attacker cannot delete. Expired locks are excluded: removing them after expiry is allowed
    by design, so trying proves nothing."""
    live = [
        e
        for e in newest_first(entries)
        if e.manifest is not None and e.lock_until is not None and e.lock_until > now
    ]
    return live[:limit]


def manifest_versions(client: Any, bucket: str) -> list[tuple[str, str]]:
    """(key, version id) of every manifest version, including non-latest ones."""
    found: list[tuple[str, str]] = []
    paginator = client.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket, Prefix="backups/"):
        for version in page.get("Versions", []):
            if version["Key"].endswith(MANIFEST_SUFFIX):
                found.append((version["Key"], version["VersionId"]))
    return found


def read_entry(client: Any, bucket: str, key: str, version_id: str) -> CatalogEntry:
    manifest: dict[str, Any] | None = None
    problem = ""
    try:
        body = client.get_object(Bucket=bucket, Key=key, VersionId=version_id)["Body"].read()
        manifest = parse_manifest(body)
    except Exception as exc:  # noqa: BLE001 - one bad object must not hide the others
        problem = f"{type(exc).__name__}: {str(exc)[:120]}"
    tag = None
    try:
        tags = client.get_object_tagging(Bucket=bucket, Key=key, VersionId=version_id)
        tag = next((t["Value"] for t in tags["TagSet"] if t["Key"] == "health"), None)
    except Exception as exc:  # noqa: BLE001
        problem = problem or f"tagging: {type(exc).__name__}"
    mode = until = None
    try:
        retention = client.get_object_retention(Bucket=bucket, Key=key, VersionId=version_id)
        mode = retention["Retention"].get("Mode")
        until = retention["Retention"].get("RetainUntilDate")
    except Exception as exc:  # noqa: BLE001
        problem = problem or f"retention: {type(exc).__name__}"
    return CatalogEntry(key, version_id, manifest, tag, mode, until, problem)


def list_backups(client: Any, bucket: str) -> list[CatalogEntry]:
    entries = [
        read_entry(client, bucket, key, vid) for key, vid in manifest_versions(client, bucket)
    ]
    return newest_first(entries)


def print_catalog(entries: list[CatalogEntry], console: Any) -> None:
    from rich.table import Table

    table = Table(title=f"Backups in the vault ({len(entries)}), newest first")
    for column in ("Dump started (UTC)", "Tag", "Manifest", "Max order", "Lock", "Locked until"):
        table.add_column(column)
    for e in entries:
        if e.manifest is None:
            table.add_row(
                e.manifest_key.rsplit("/", 1)[-1],
                e.tag or "-",
                f"[red]{e.problem}[/red]",
                "-",
                e.lock_mode or "-",
                "-",
            )
            continue
        health = e.manifest["health"]["status"]
        mismatch = e.tag != health
        tag = f"[red]{e.tag}[/red]" if mismatch else (e.tag or "-")
        colour = "green" if health == "clean" else "red"
        until = f"{e.lock_until:%H:%M:%S}Z" if e.lock_until else "-"
        table.add_row(
            f"{e.started:%Y-%m-%d %H:%M:%S}",
            tag,
            f"[{colour}]{health}[/{colour}]",
            str(e.manifest["max_order_id"]),
            e.lock_mode or "-",
            until,
        )
    console.print(table)
