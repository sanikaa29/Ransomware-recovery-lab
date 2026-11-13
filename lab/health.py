"""Content health checks: is this database's data intact?

``evaluate`` holds the rules and is pure (unit-tested); ``check_database`` gathers the facts
with SQL. Used by backup, detect and restore.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from lab.schema import TABLES

# One pattern for both Python and Postgres (``~``). Encrypted values never contain "@".
EMAIL_PATTERN = r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}$"
EMAIL_RE = re.compile(EMAIL_PATTERN)
MIN_VALID_EMAIL_PERCENT = 99
MAX_ROW_DROP_PERCENT = 5
RANSOM_TABLE = "readme_ransom"


@dataclass(frozen=True)
class HealthReport:
    status: Literal["clean", "suspect"]
    reasons: tuple[str, ...]
    stats: dict[str, Any] = field(default_factory=dict)

    @property
    def is_clean(self) -> bool:
        return self.status == "clean"


def evaluate(
    *,
    email_total: int | None,
    email_valid: int,
    ransom_table_exists: bool,
    row_counts: dict[str, int | None],
    baseline: dict[str, int] | None = None,
) -> HealthReport:
    """Apply the three rules. Integer maths, so the boundaries are exact.

    - at least 99% of customer e-mails must be valid (exactly 99% passes);
    - the ransom-note table must not exist;
    - no table may lose more than 5% of its rows versus ``baseline`` (exactly 5% passes).
    """
    reasons: list[str] = []
    if email_total is None:
        reasons.append("customers table is missing")
    elif email_total == 0:
        reasons.append("customers table is empty")
    elif email_valid * 100 < email_total * MIN_VALID_EMAIL_PERCENT:
        pct = 100 * email_valid / email_total
        reasons.append(
            f"only {pct:.2f}% of customer emails are valid "
            f"(need at least {MIN_VALID_EMAIL_PERCENT}%)"
        )
    if ransom_table_exists:
        reasons.append(f"ransom note table {RANSOM_TABLE.upper()} exists")
    for table, before in sorted((baseline or {}).items()):
        now = row_counts.get(table)
        if before <= 0:
            continue
        if now is None:
            reasons.append(f"table {table} is missing (had {before} rows)")
        elif now * 100 < before * (100 - MAX_ROW_DROP_PERCENT):
            drop = 100 * (before - now) / before
            reasons.append(
                f"{table} rows fell from {before} to {now} "
                f"({drop:.1f}% drop, limit {MAX_ROW_DROP_PERCENT}%)"
            )
    stats = {
        "row_counts": dict(row_counts),
        "email_total": email_total,
        "email_valid": email_valid,
        "ransom_table_exists": ransom_table_exists,
    }
    return HealthReport("suspect" if reasons else "clean", tuple(reasons), stats)


def check_database(conn: Any, baseline: dict[str, int] | None = None) -> HealthReport:
    """Gather the facts from a live database and evaluate them."""
    with conn.cursor() as cur:
        cur.execute(
            "SELECT lower(table_name) FROM information_schema.tables WHERE table_schema = 'public'"
        )
        present = {row[0] for row in cur.fetchall()}
        counts: dict[str, int | None] = {}
        for table in TABLES:
            if table in present:
                cur.execute(f"SELECT count(*) FROM {table}")
                counts[table] = cur.fetchone()[0]
            else:
                counts[table] = None
        email_total: int | None = None
        email_valid = 0
        if "customers" in present:
            cur.execute(
                "SELECT count(*), count(*) FILTER (WHERE email ~ %s) FROM customers",
                (EMAIL_PATTERN,),
            )
            email_total, email_valid = cur.fetchone()
    return evaluate(
        email_total=email_total,
        email_valid=email_valid,
        ransom_table_exists=RANSOM_TABLE in present,
        row_counts=counts,
        baseline=baseline,
    )


def load_baseline(path: str | Path) -> dict[str, int]:
    """Read ``row_counts`` from a backup manifest JSON file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    counts = data.get("row_counts") if isinstance(data, dict) else None
    if not isinstance(counts, dict) or not all(isinstance(v, int) for v in counts.values()):
        raise ValueError(f"{path}: expected a JSON object with integer 'row_counts'")
    return counts


def print_health(report: HealthReport, console: Any, title: str) -> None:
    from rich.table import Table

    table = Table(title=f"Row counts ({title})")
    table.add_column("Table")
    table.add_column("Rows", justify="right")
    for name, count in report.stats["row_counts"].items():
        table.add_row(name, "missing" if count is None else f"{count:,}")
    console.print(table)
    if report.is_clean:
        console.print("[bold green]HEALTH: CLEAN[/bold green]")
        return
    console.print("[bold red]HEALTH: SUSPECT[/bold red]")
    for reason in report.reasons:
        console.print(f"  - {reason}")
