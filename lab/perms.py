"""Permission probe: what can each identity actually do? Prints real results, never assumes.

Expectations: the backup writer can write/list/read/tag backups in its bucket and nothing
administrative; the attacker (stolen admin) still cannot destroy locked data.

Safety: this probe never deletes the real backup bucket. Bucket deletion is tried on a
scratch bucket that holds a locked object. If the writer cannot upload locked objects, the
locked test object is seeded with the admin identity instead, so later rows stay meaningful.
"""

from __future__ import annotations

import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from botocore.client import BaseClient
from rich.console import Console
from rich.markup import escape
from rich.table import Table

from lab.config import Settings
from lab.storage import ensure_locked_bucket, make_client, provision, try_call
from lab.vault_rules import Expectation, Outcome, judge, retention_until

RETENTION_MINUTES = 2
SCRATCH_BUCKET = "perms-tmp"


@dataclass(frozen=True)
class PermRow:
    identity: str
    action: str
    expected: Expectation
    outcome: Outcome
    code: str
    verdict: str


def run_perms(settings: Settings) -> list[PermRow]:
    provision(settings)
    admin = make_client(settings, "attacker")
    writer = make_client(settings, "writer")
    anonymous = make_client(settings, "anonymous")
    bogus = make_client(settings, "bogus")
    ensure_locked_bucket(admin, SCRATCH_BUCKET)

    bucket = settings.s3_bucket
    until = retention_until(datetime.now(UTC), RETENTION_MINUTES)
    run = uuid.uuid4().hex[:12]
    locked_key = f"perms/{run}-locked.txt"
    unlocked_key = f"perms/{run}-unlocked.txt"
    two_step_key = f"perms/{run}-twostep.txt"
    state: dict[str, str] = {}
    rows: list[PermRow] = []

    def probe(
        identity: str, action: str, expected: Expectation, call: Callable[[], object]
    ) -> None:
        try:
            outcome, code = try_call(call)
        except KeyError:  # an earlier seed step failed, so there is nothing to act on
            outcome, code = "error", "skipped (earlier step failed)"
        rows.append(
            PermRow(identity, action, expected, outcome, code, judge(expected, outcome, code))
        )

    def locked_put(client: BaseClient, target: str, key: str, mode: str = "COMPLIANCE") -> str:
        response = client.put_object(
            Bucket=target,
            Key=key,
            Body=b"x",
            ObjectLockMode=mode,
            ObjectLockRetainUntilDate=until,
        )
        return str(response.get("VersionId", ""))

    def set_state(name: str, call: Callable[[], str]) -> Callable[[], None]:
        def run_and_store() -> None:
            state[name] = call()

        return run_and_store

    # 1. Authentication must be on at all. If these are allowed, every other row is meaningless.
    probe(
        "anonymous",
        "List the backup bucket with no credentials",
        "deny",
        lambda: anonymous.list_objects_v2(Bucket=bucket),
    )
    probe(
        "anonymous",
        "Write an object with no credentials",
        "deny",
        lambda: anonymous.put_object(Bucket=bucket, Key=f"perms/{run}-anon.txt", Body=b"x"),
    )
    probe(
        "unknown key",
        "List the backup bucket with made-up credentials",
        "deny",
        lambda: bogus.list_objects_v2(Bucket=bucket),
    )

    # 2. What the backup writer needs to do its job.
    probe(
        "writer",
        "Write an object with COMPLIANCE lock",
        "allow",
        set_state("locked", lambda: locked_put(writer, bucket, locked_key)),
    )
    if "locked" not in state:
        probe(
            "admin (setup)",
            "Seed the locked test object instead (writer could not)",
            "record",
            set_state("locked", lambda: locked_put(admin, bucket, locked_key)),
        )
    probe(
        "writer",
        "Write an unlocked object",
        "allow",
        set_state(
            "unlocked",
            lambda: str(
                writer.put_object(Bucket=bucket, Key=unlocked_key, Body=b"x").get("VersionId", "")
            ),
        ),
    )
    probe(
        "writer",
        "List objects",
        "allow",
        lambda: writer.list_objects_v2(Bucket=bucket, Prefix="perms/"),
    )
    probe(
        "writer",
        "Read the locked version",
        "allow",
        lambda: writer.get_object(Bucket=bucket, Key=locked_key, VersionId=state["locked"]),
    )
    probe(
        "writer",
        "Tag the locked version",
        "allow",
        lambda: writer.put_object_tagging(
            Bucket=bucket,
            Key=locked_key,
            VersionId=state["locked"],
            Tagging={"TagSet": [{"Key": "health", "Value": "clean"}]},
        ),
    )

    # What restore will need from the writer identity later.
    probe(
        "writer",
        "Read the tags of the locked version (restore needs this)",
        "allow",
        lambda: writer.get_object_tagging(Bucket=bucket, Key=locked_key, VersionId=state["locked"]),
    )
    probe(
        "writer",
        "List object versions (restore needs this)",
        "allow",
        lambda: writer.list_object_versions(Bucket=bucket, Prefix="perms/"),
    )

    # 3. Diagnosis: which route lets the writer lock an object? Recorded, not judged.
    probe(
        "writer",
        "Diagnosis: upload with GOVERNANCE-mode retention headers",
        "record",
        lambda: locked_put(writer, bucket, f"perms/{run}-gov.txt", "GOVERNANCE"),
    )
    probe(
        "writer",
        "Diagnosis: upload unlocked (step 1 of a two-step lock)",
        "record",
        set_state(
            "two_step",
            lambda: str(
                writer.put_object(Bucket=bucket, Key=two_step_key, Body=b"x").get("VersionId", "")
            ),
        ),
    )
    probe(
        "writer",
        "Diagnosis: then set COMPLIANCE retention (step 2)",
        "record",
        lambda: writer.put_object_retention(
            Bucket=bucket,
            Key=two_step_key,
            VersionId=state["two_step"],
            Retention={"Mode": "COMPLIANCE", "RetainUntilDate": until},
        ),
    )
    probe(
        "writer",
        "Diagnosis: read retention of the locked version",
        "record",
        lambda: writer.get_object_retention(
            Bucket=bucket, Key=locked_key, VersionId=state["locked"]
        ),
    )

    # 4. What the writer must NOT be able to do.
    probe(
        "writer",
        "Delete an UNLOCKED version (is Write also delete?)",
        "record",
        lambda: writer.delete_object(Bucket=bucket, Key=unlocked_key, VersionId=state["unlocked"]),
    )
    probe(
        "writer",
        "Delete the locked version",
        "deny",
        lambda: writer.delete_object(Bucket=bucket, Key=locked_key, VersionId=state["locked"]),
    )
    probe(
        "writer",
        "Create a bucket",
        "deny",
        lambda: writer.create_bucket(Bucket="writer-should-fail"),
    )
    probe(
        "writer",
        "Suspend versioning",
        "deny",
        lambda: writer.put_bucket_versioning(
            Bucket=bucket, VersioningConfiguration={"Status": "Suspended"}
        ),
    )
    probe(
        "writer",
        "Shorten retention on the locked version",
        "deny",
        lambda: writer.put_object_retention(
            Bucket=bucket,
            Key=locked_key,
            VersionId=state["locked"],
            Retention={
                "Mode": "COMPLIANCE",
                "RetainUntilDate": datetime.now(UTC) + timedelta(seconds=30),
            },
        ),
    )
    probe(
        "writer",
        "Delete a different bucket (is the admin scope really per-bucket?)",
        "deny",
        lambda: writer.delete_bucket(Bucket=SCRATCH_BUCKET),
    )
    probe(
        "writer",
        "Write to a different bucket (is the scope really per-bucket?)",
        "deny",
        lambda: writer.put_object(Bucket=SCRATCH_BUCKET, Key="scope-test.txt", Body=b"x"),
    )

    # 5. The simulated attacker, holding stolen admin credentials, against locked data.
    probe(
        "attacker",
        "Delete the locked version",
        "deny",
        lambda: admin.delete_object(Bucket=bucket, Key=locked_key, VersionId=state["locked"]),
    )
    probe(
        "attacker",
        "Shorten retention on the locked version",
        "deny",
        lambda: admin.put_object_retention(
            Bucket=bucket,
            Key=locked_key,
            VersionId=state["locked"],
            Retention={
                "Mode": "COMPLIANCE",
                "RetainUntilDate": datetime.now(UTC) + timedelta(seconds=30),
            },
        ),
    )
    probe(
        "attacker",
        "Suspend versioning",
        "deny",
        lambda: admin.put_bucket_versioning(
            Bucket=bucket, VersioningConfiguration={"Status": "Suspended"}
        ),
    )
    probe(
        "admin (setup)",
        "Put a locked object into the scratch bucket",
        "record",
        lambda: locked_put(admin, SCRATCH_BUCKET, f"perms/{run}-scratch.txt"),
    )
    probe(
        "attacker",
        "Delete a bucket that holds a locked object (scratch bucket)",
        "deny",
        lambda: admin.delete_bucket(Bucket=SCRATCH_BUCKET),
    )
    probe(
        "attacker",
        "Delete newest object, no version id (delete marker?)",
        "record",
        lambda: admin.delete_object(Bucket=bucket, Key=locked_key),
    )

    # 6. After all of that, the locked version must still be there.
    probe(
        "admin (verify)",
        "Locked version still readable after every attack above",
        "allow",
        lambda: admin.get_object(Bucket=bucket, Key=locked_key, VersionId=state["locked"]),
    )
    return rows


def print_perms(rows: list[PermRow], console: Console) -> None:
    table = Table(title="Permission probe (real results)")
    for column in ("Identity", "Action", "Expected", "Result", "Error code", "Verdict"):
        table.add_column(column)
    colors = {"OK": "green", "INFO": "yellow", "MISMATCH": "red"}
    for r in rows:
        color = colors[r.verdict]
        table.add_row(
            r.identity,
            r.action,
            r.expected,
            r.outcome,
            escape(r.code),
            f"[{color}]{r.verdict}[/{color}]",
        )
    console.print(table)
    mismatches = sum(r.verdict == "MISMATCH" for r in rows)
    console.print(f"{mismatches} mismatch(es). INFO rows are recorded, not judged.")
    console.print(
        "BucketNotEmpty on a bucket deletion means the bucket was protected by its contents. "
        "The lock is what stops anyone emptying it: see the 'Delete the locked version' rows."
    )
