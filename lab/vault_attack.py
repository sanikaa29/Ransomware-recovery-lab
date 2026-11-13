"""What the attacker tries against the vault with the stolen admin credentials.

Six attempts, each judged by what SURVIVED, not by the error code. Only backups whose lock is
still running are targeted (see ``catalog.locked_targets``).
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from lab.catalog import CatalogEntry
from lab.storage import try_call
from lab.vault_rules import Outcome, describe_result, same_instant

OVERWRITE_BODY = b"ENCRYPTED BY LAB ATTACKER SIMULATION - NOT A BACKUP"


@dataclass(frozen=True)
class Attempt:
    action: str
    result: str
    code: str


def _survives(check: Any) -> bool:
    try:
        return bool(check())
    except (BotoCoreError, ClientError):
        return False


def _single(action: str, call: Any, intact: Any, suffix: str = "") -> Attempt:
    outcome, code = try_call(call)
    result = describe_result(outcome, _survives(intact), code)
    if outcome == "allowed" and suffix and result == "ALLOWED, DATA INTACT":
        result += f" ({suffix})"
    return Attempt(action, result, code)


def _bulk(action: str, outcomes: list[tuple[Outcome, str]], survivors: int) -> Attempt:
    total = len(outcomes)
    if survivors < total:
        return Attempt(action, f"DESTROYED {total - survivors} of {total}", "-")
    first_bad = next((o for o, _ in outcomes if o != "blocked"), "blocked")
    codes = Counter(code for _, code in outcomes if code != "-")
    code = codes.most_common(1)[0][0] if codes else "-"
    return Attempt(action, f"{describe_result(first_bad, True, code)} ({total} versions)", code)


def _version_ids(targets: list[CatalogEntry]) -> list[tuple[str, str]]:
    """(key, version id) of every manifest and dump the attacker could see."""
    pairs: list[tuple[str, str]] = []
    for entry in targets:
        pairs.append((entry.manifest_key, entry.manifest_version_id))
        manifest = entry.manifest or {}
        if manifest.get("dump_version_id"):
            pairs.append((manifest["dump_key"], manifest["dump_version_id"]))
    return pairs


def run_attempts(client: Any, bucket: str, targets: list[CatalogEntry]) -> list[Attempt]:
    """Run the six attempts against the locked backups in ``targets`` (newest first)."""
    newest = (targets[0].manifest or {}) if targets else {}
    key, vid, size = newest["dump_key"], newest["dump_version_id"], newest["size_bytes"]

    def original_intact() -> bool:
        return client.head_object(Bucket=bucket, Key=key, VersionId=vid)["ContentLength"] == size

    before = client.get_object_retention(Bucket=bucket, Key=key, VersionId=vid)["Retention"]

    def retention_unchanged() -> bool:
        now = client.get_object_retention(Bucket=bucket, Key=key, VersionId=vid)["Retention"]
        return now["Mode"] == before["Mode"] and same_instant(
            now["RetainUntilDate"], before["RetainUntilDate"]
        )

    attempts = [
        _single(
            "Delete newest backup (no version id)",
            lambda: client.delete_object(Bucket=bucket, Key=key),
            original_intact,
            "delete marker only",
        )
    ]
    pairs = _version_ids(targets)
    outcomes = [
        try_call(lambda k=k, v=v: client.delete_object(Bucket=bucket, Key=k, VersionId=v))
        for k, v in pairs
    ]
    alive = sum(
        _survives(lambda k=k, v=v: client.head_object(Bucket=bucket, Key=k, VersionId=v))
        for k, v in pairs
    )
    attempts.append(_bulk("Delete locked backup versions", outcomes, alive))
    attempts.append(
        _single(
            "Overwrite newest backup with garbage",
            lambda: client.put_object(Bucket=bucket, Key=key, Body=OVERWRITE_BODY),
            original_intact,
            "new version added",
        )
    )
    shorter = datetime.now(UTC) + timedelta(seconds=30)
    attempts.append(
        _single(
            "Shorten retention to 30 seconds",
            lambda: client.put_object_retention(
                Bucket=bucket,
                Key=key,
                VersionId=vid,
                Retention={"Mode": "COMPLIANCE", "RetainUntilDate": shorter},
            ),
            retention_unchanged,
        )
    )
    attempts.append(
        _single(
            "Suspend bucket versioning",
            lambda: client.put_bucket_versioning(
                Bucket=bucket, VersioningConfiguration={"Status": "Suspended"}
            ),
            lambda: client.get_bucket_versioning(Bucket=bucket).get("Status") == "Enabled",
        )
    )
    attempts.append(
        _single(
            "Delete the bucket",
            lambda: client.delete_bucket(Bucket=bucket),
            lambda: client.head_bucket(Bucket=bucket),
        )
    )
    return attempts


def count_survivors(client: Any, bucket: str, targets: list[CatalogEntry]) -> tuple[int, int]:
    """(versions still retrievable, versions that were targeted)."""
    pairs = _version_ids(targets)
    alive = sum(
        _survives(lambda k=k, v=v: client.head_object(Bucket=bucket, Key=k, VersionId=v))
        for k, v in pairs
    )
    return alive, len(pairs)


def print_attempts(attempts: list[Attempt], console: Any) -> None:
    from rich.table import Table

    table = Table(title="Attacker vs. the vault (stolen admin credentials)")
    for column in ("Attempted action", "Result", "Error code"):
        table.add_column(column)
    for item in attempts:
        bad = item.result.startswith(("DESTROYED", "ERROR", "UNSUPPORTED"))
        colour = "red" if bad else ("green" if item.result.startswith("BLOCKED") else "yellow")
        table.add_row(item.action, f"[{colour}]{item.result}[/{colour}]", item.code)
    console.print(table)
