"""Watch the production database and raise the alarm the first time its health is suspect."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from lab import timeline
from lab.config import LAST_CLEAN_PATH, Settings
from lab.health import HealthReport, check_database, load_baseline

POLL_SECONDS = 5.0


def watch_until_suspect(
    check: Callable[[], HealthReport | None],
    *,
    interval: float = POLL_SECONDS,
    max_polls: int | None = None,
    sleep: Callable[[float], None] = time.sleep,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    on_poll: Callable[[datetime, HealthReport | None], None] | None = None,
) -> tuple[HealthReport, datetime] | None:
    """Poll ``check`` every ``interval`` seconds. ``check`` returns None when the database
    could not be read (not an alarm). Returns (report, time of detection) at the first suspect
    result, or None when ``max_polls`` ran out."""
    polls = 0
    while max_polls is None or polls < max_polls:
        if polls:
            sleep(interval)
        polls += 1
        report = check()
        moment = now()
        if on_poll:
            on_poll(moment, report)
        if report is not None and not report.is_clean:
            return report, moment
    return None


def _check_production(settings: Settings, console: Any) -> HealthReport | None:
    import psycopg

    from lab.db import connect

    baseline = load_baseline(LAST_CLEAN_PATH) if LAST_CLEAN_PATH.is_file() else None
    try:
        with connect(settings) as conn:
            return check_database(conn, baseline)
    except psycopg.Error as exc:
        first = (str(exc).strip().splitlines() or [type(exc).__name__])[0][:120]
        console.print(f"[yellow]{datetime.now(UTC):%H:%M:%S}Z cannot read the database: {first}[/]")
        return None


def run_detect(
    settings: Settings, console: Any, *, interval: float = POLL_SECONDS, timeout: float = 0
) -> int:
    """Exit code 0 once an incident is detected, 1 if ``timeout`` seconds pass without one."""
    console.print(f"Watching {settings.pg_db} every {interval:g}s. Ctrl+C to stop.")
    started = time.monotonic()

    def show(moment: datetime, report: HealthReport | None) -> None:
        if report is not None and report.is_clean:
            console.print(f"[dim]{moment:%H:%M:%S}Z health clean[/dim]")

    polls = None
    if timeout > 0:
        polls = max(1, int(timeout // interval) + 1)
    try:
        found = watch_until_suspect(
            lambda: _check_production(settings, console),
            interval=interval,
            max_polls=polls,
            on_poll=show,
        )
    except KeyboardInterrupt:
        console.print("Stopped.")
        return 130
    if found is None:
        console.print(f"No incident in {time.monotonic() - started:.0f}s.")
        return 1
    report, moment = found
    timeline.record("incident_detected", moment)
    console.print(f"[bold white on red] INCIDENT [/] {moment:%H:%M:%S}Z database health is SUSPECT")
    for reason in report.reasons:
        console.print(f"[red]  - {reason}[/red]")
    return 0
