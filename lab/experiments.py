"""Find the narrowest writer action set that can upload with COMPLIANCE lock.

Each candidate identity (see setup_env.CANDIDATES) runs the same four operations against the
real backup bucket. Run after `python -m lab.setup_env --experiments` and a vault restart.
"""

from __future__ import annotations

import json
import uuid
from collections.abc import Callable
from datetime import UTC, datetime

from rich.console import Console
from rich.markup import escape
from rich.table import Table

from lab.config import LAB_DIR, Settings
from lab.setup_env import CANDIDATES, EXPERIMENT_KEYS_FILE
from lab.storage import client_with_keys, try_call
from lab.vault_rules import retention_until

RETENTION_MINUTES = 2
TESTS = (
    "Upload with COMPLIANCE headers",
    "Upload, then set retention (two-step)",
    "List objects",
    "Tag an object",
)


def load_keys() -> dict[str, dict[str, str]]:
    path = LAB_DIR / EXPERIMENT_KEYS_FILE
    if not path.is_file():
        raise FileNotFoundError(
            "no experiment identities. Run: python -m lab.setup_env --experiments, "
            "then: docker compose restart vault"
        )
    return json.loads(path.read_text(encoding="utf-8"))


def run_experiments(settings: Settings) -> list[tuple[str, str, str, str]]:
    """Rows of (candidate, test, result, error code)."""
    bucket = settings.s3_bucket
    until = retention_until(datetime.now(UTC), RETENTION_MINUTES)
    rows: list[tuple[str, str, str, str]] = []
    for name, keys in load_keys().items():
        client = client_with_keys(settings, keys["access"], keys["secret"])
        prefix = f"experiments/{name}/{uuid.uuid4().hex}"
        state: dict[str, str] = {}

        def direct(client=client, prefix=prefix) -> None:
            client.put_object(
                Bucket=bucket,
                Key=f"{prefix}-direct.txt",
                Body=b"x",
                ObjectLockMode="COMPLIANCE",
                ObjectLockRetainUntilDate=until,
            )

        def two_step(client=client, prefix=prefix, state=state) -> None:
            key = f"{prefix}-twostep.txt"
            version = client.put_object(Bucket=bucket, Key=key, Body=b"x")["VersionId"]
            state["key"], state["version"] = key, version
            client.put_object_retention(
                Bucket=bucket,
                Key=key,
                VersionId=version,
                Retention={"Mode": "COMPLIANCE", "RetainUntilDate": until},
            )

        def listing(client=client, prefix=prefix) -> None:
            client.list_objects_v2(Bucket=bucket, Prefix=prefix)

        def tag(client=client, state=state) -> None:
            client.put_object_tagging(
                Bucket=bucket,
                Key=state["key"],
                VersionId=state["version"],
                Tagging={"TagSet": [{"Key": "health", "Value": "clean"}]},
            )

        steps: tuple[Callable[[], None], ...] = (direct, two_step, listing, tag)
        for test, step in zip(TESTS, steps, strict=True):
            try:
                outcome, code = try_call(step)
            except KeyError:
                outcome, code = "error", "skipped (needs the two-step upload)"
            rows.append((name, test, outcome, code))
    return rows


def print_experiments(rows: list[tuple[str, str, str, str]], console: Console) -> None:
    table = Table(title="Writer candidates (real results)")
    for column in ("Candidate", "Actions", "Test", "Result", "Error code"):
        table.add_column(column)
    previous = ""
    for name, test, outcome, code in rows:
        style = "green" if outcome == "allowed" else "red"
        actions = ", ".join(CANDIDATES[name]).replace("{b}", "bucket") if name != previous else ""
        table.add_row(
            name if name != previous else "",
            actions,
            test,
            f"[{style}]{outcome}[/{style}]",
            escape(code),
        )
        previous = name
    console.print(table)
    console.print(
        "Pick the narrowest set where 'Upload with COMPLIANCE headers' (or the two-step) is "
        "allowed. Then run `make setup` (removes these identities) and restart the vault."
    )
