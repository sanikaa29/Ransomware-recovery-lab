"""Vault capability gate: does this vault REALLY enforce COMPLIANCE Object Lock?

Writes a locked object, then tries to destroy it with the strongest identity we have.
All destructive attempts must fail AND the object must demonstrably survive.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from botocore.exceptions import BotoCoreError, ClientError
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from lab.config import Settings
from lab.storage import (
    clock_skew,
    ensure_locked_bucket,
    make_client,
    object_lock_enabled,
    try_call,
)
from lab.vault_rules import extract_error, lock_verdict, retention_until, same_instant

TMP_BUCKET = "lockcheck-tmp"
RETENTION_MINUTES = 2


@dataclass
class LockcheckReport:
    passed: bool
    rows: list[tuple[str, str, str]] = field(default_factory=list)  # action, outcome, code
    problems: list[str] = field(default_factory=list)
    skew: float | None = None


def _failed(problem: str, rows: list[tuple[str, str, str]] | None = None) -> LockcheckReport:
    return LockcheckReport(False, rows or [], [problem])


def run_lockcheck(settings: Settings) -> LockcheckReport:
    admin = make_client(settings, "attacker")
    try:
        return _run(settings, admin)
    except (BotoCoreError, ClientError) as exc:
        code, _ = extract_error(exc)
        return _failed(f"could not complete the check ({code}); is the vault up? try `make up`")


def _run(settings: Settings, admin) -> LockcheckReport:  # noqa: ANN001 - boto client is dynamic
    ensure_locked_bucket(admin, TMP_BUCKET)
    lock_enabled = object_lock_enabled(admin, TMP_BUCKET)
    key = f"lockcheck/{uuid.uuid4().hex}.txt"
    now = datetime.now(UTC)
    put = admin.put_object(
        Bucket=TMP_BUCKET,
        Key=key,
        Body=b"lockcheck",
        ObjectLockMode="COMPLIANCE",
        ObjectLockRetainUntilDate=retention_until(now, RETENTION_MINUTES),
    )
    version_id = put.get("VersionId")
    if not version_id:
        return _failed("vault returned no VersionId: versioning is not active on the bucket")
    before = admin.get_object_retention(Bucket=TMP_BUCKET, Key=key, VersionId=version_id)
    mode = before["Retention"].get("Mode")
    until_before = before["Retention"].get("RetainUntilDate")

    attempts = [
        (
            "Delete the locked object version",
            lambda: admin.delete_object(Bucket=TMP_BUCKET, Key=key, VersionId=version_id),
        ),
        (
            "Shorten its retention",
            lambda: admin.put_object_retention(
                Bucket=TMP_BUCKET,
                Key=key,
                VersionId=version_id,
                Retention={
                    "Mode": "COMPLIANCE",
                    "RetainUntilDate": datetime.now(UTC) + timedelta(seconds=30),
                },
            ),
        ),
        (
            "Suspend bucket versioning",
            lambda: admin.put_bucket_versioning(
                Bucket=TMP_BUCKET, VersioningConfiguration={"Status": "Suspended"}
            ),
        ),
    ]
    results = [(action, *try_call(call)) for action, call in attempts]

    # Error codes alone can lie, so prove the object survived and the lock is unchanged.
    intact, unchanged = True, True
    try:
        admin.head_object(Bucket=TMP_BUCKET, Key=key, VersionId=version_id)
        after = admin.get_object_retention(Bucket=TMP_BUCKET, Key=key, VersionId=version_id)
        until_after = after["Retention"].get("RetainUntilDate")
        unchanged = (
            until_before is not None
            and until_after is not None
            and same_instant(until_before, until_after)
        )
    except (BotoCoreError, ClientError):
        intact = False
    status = admin.get_bucket_versioning(Bucket=TMP_BUCKET).get("Status")

    passed, problems = lock_verdict(
        [outcome for _, outcome, _ in results],
        lock_enabled=lock_enabled,
        mode=mode,
        intact=intact,
        retention_unchanged=unchanged,
        versioning_enabled=status == "Enabled",
    )
    return LockcheckReport(passed, list(results), problems, clock_skew(admin, TMP_BUCKET))


def print_report(report: LockcheckReport, console: Console) -> None:
    table = Table(title="Vault capability gate (lockcheck)")
    for column in ("Attempted action", "Result", "Error code"):
        table.add_column(column)
    for action, outcome, code in report.rows:
        style = "green" if outcome == "blocked" else "red"
        table.add_row(action, f"[{style}]{outcome.upper()}[/{style}]", escape(code))
    console.print(table)
    if report.skew is not None:
        console.print(f"Clock skew (vault minus host): {report.skew:+.1f}s")
        if abs(report.skew) > 30:
            console.print(
                "[yellow]Warning: clocks differ a lot; retention math may surprise you.[/yellow]"
            )
    if report.passed:
        console.print(
            "[bold green]LOCKCHECK: PASS[/bold green]  COMPLIANCE lock is really enforced."
        )
        return
    console.print("[bold red]LOCKCHECK: FAIL[/bold red]")
    for problem in report.problems:
        console.print(f"  - {escape(problem)}")
    console.print(
        "Do not build on this vault. Switch to the fallback (RustFS, image rustfs/rustfs) "
        "and re-run `lab lockcheck`."
    )
