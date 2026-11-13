"""``lab`` command-line interface. Phase 1 provides ``up`` and ``down``."""

from __future__ import annotations

import subprocess
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from lab.compose import all_healthy, parse_ps
from lab.config import ENV_FILE, LAB_DIR, LAST_CLEAN_PATH, ROOT

app = typer.Typer(
    help="Ransomware recovery lab: local, zero-cost, simulation only.",
    no_args_is_help=True,
    add_completion=False,
)
console = Console()
S3_CONFIG = LAB_DIR / "s3.json"


def _compose(*args: str, capture: bool = False) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["docker", "compose", *args],
            cwd=ROOT,
            text=True,
            capture_output=capture,
            check=False,
        )
    except FileNotFoundError:
        console.print("[red]docker not found.[/red] Install Docker Desktop or Docker Engine.")
        raise typer.Exit(1) from None


def _preflight() -> None:
    """Fail early: a missing bind-mount source would make Docker create a directory instead."""
    missing = [
        p
        for p, ok in ((".env", ENV_FILE.is_file()), (".lab/s3.json", S3_CONFIG.is_file()))
        if not ok
    ]
    if missing:
        console.print(
            f"[red]Not set up:[/red] missing {', '.join(missing)}. Run [bold]make setup[/bold]."
        )
        raise typer.Exit(1)


def _print_status(rows: list[dict[str, str]]) -> None:
    table = Table(title="Lab services")
    for column in ("Service", "State", "Health", "Published (localhost only)"):
        table.add_column(column)
    for row in rows:
        style = "green" if row["health"] == "healthy" else "red"
        table.add_row(
            row["service"], row["state"], f"[{style}]{row['health']}[/{style}]", row["ports"]
        )
    console.print(table)


@app.command()
def up(timeout: Annotated[int, typer.Option(help="Seconds to wait for healthy")] = 180) -> None:
    """Start postgres, postgres_restore and the vault; wait until all are healthy."""
    _preflight()
    result = _compose("up", "-d", "--wait", "--wait-timeout", str(timeout))
    status = _compose("ps", "--all", "--format", "json", capture=True)
    rows = parse_ps(status.stdout)
    _print_status(rows)
    if result.returncode != 0 or not all_healthy(rows):
        console.print(
            "[red]Not all services are healthy.[/red] Inspect: docker compose logs <service>"
        )
        raise typer.Exit(1)
    console.print("[green]All services healthy.[/green]")
    from botocore.exceptions import BotoCoreError, ClientError

    from lab.config import Settings
    from lab.storage import provision

    settings = Settings.load()
    try:
        provision(settings)
    except (BotoCoreError, ClientError, RuntimeError) as exc:
        console.print(f"[red]Vault provisioning failed:[/red] {type(exc).__name__}: {exc}")
        raise typer.Exit(1) from None
    console.print(f"[green]Bucket '{settings.s3_bucket}' ready with Object Lock enabled.[/green]")


@app.command()
def lockcheck() -> None:
    """Prove the vault really enforces COMPLIANCE Object Lock (gate for everything else)."""
    from lab.config import Settings
    from lab.lockcheck import print_report, run_lockcheck

    report = run_lockcheck(Settings.load())
    print_report(report, console)
    if not report.passed:
        raise typer.Exit(1)


@app.command()
def perms() -> None:
    """Probe what the backup-writer and attacker identities can really do."""
    from lab.config import Settings
    from lab.perms import print_perms, run_perms

    rows = run_perms(Settings.load())
    print_perms(rows, console)
    if any(r.verdict == "MISMATCH" for r in rows):
        raise typer.Exit(1)


@app.command()
def experiments() -> None:
    """Test candidate writer permission sets (see `python -m lab.setup_env --experiments`)."""
    from lab.config import Settings
    from lab.experiments import print_experiments, run_experiments

    try:
        rows = run_experiments(Settings.load())
    except FileNotFoundError as exc:
        console.print(f"[red]{exc}[/red]")
        raise typer.Exit(1) from None
    print_experiments(rows, console)


def _fail(message: str) -> typer.Exit:
    console.print(f"[red]{message}[/red]")
    return typer.Exit(1)


def _db_unreachable(settings, exc: Exception) -> typer.Exit:  # noqa: ANN001
    first = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    return _fail(
        f"Cannot use Postgres on {settings.pg_host}:{settings.pg_port} "
        f"(restore: {settings.restore_pg_port}): {first}. Is the stack up? Try `make up`."
    )


@app.command()
def seed(
    customers: int = 5000,
    products: int = 200,
    orders: int = 50000,
) -> None:
    """Create tables and load deterministic demo data. Idempotent: truncates and reloads."""
    import psycopg

    from lab.config import Settings
    from lab.db import connect, max_order_id
    from lab.guard import GuardError, require_local_lab_db
    from lab.seed import Sizes, generate, load

    settings = Settings.load()
    try:
        require_local_lab_db(settings)
    except GuardError as exc:
        raise _fail(f"Refusing to seed: {exc}") from None
    LAST_CLEAN_PATH.unlink(missing_ok=True)  # new data set: old baseline no longer applies
    console.print("Generating deterministic data...")
    data = generate(Sizes(customers, products, orders))
    console.print("Loading with COPY...")
    try:
        with connect(settings) as conn:
            counts = load(conn, data)
            newest = max_order_id(conn)
    except psycopg.Error as exc:
        raise _db_unreachable(settings, exc) from None
    table = Table(title="Seeded shopdb")
    table.add_column("Table")
    table.add_column("Rows", justify="right")
    for name, count in counts.items():
        table.add_row(name, f"{count:,}")
    console.print(table)
    console.print(f"[green]Done.[/green] Newest order id: {newest}")


@app.command("app-sim")
def app_sim(
    interval: Annotated[float, typer.Option(help="Seconds between new orders")] = 1.0,
) -> None:
    """Insert one new order about every second until stopped (Ctrl+C)."""
    from lab.app_sim import LOG_PATH, run
    from lab.config import Settings

    console.print(f"Simulating shop traffic. Logging to {LOG_PATH}. Ctrl+C to stop.")
    code = run(Settings.load(), interval=interval, console=console)
    if code:
        raise typer.Exit(code)


@app.command()
def backup(
    loop: Annotated[
        bool, typer.Option("--loop", help="Keep backing up every BACKUP_INTERVAL_SECONDS")
    ] = False,
) -> None:
    """Take a consistent, COMPLIANCE-locked backup (dump + manifest) into the vault."""
    import psycopg
    from botocore.exceptions import BotoCoreError, ClientError

    from lab.backup import BackupError, print_result, run_backup_once, run_loop
    from lab.config import Settings

    settings = Settings.load()
    if loop:
        raise typer.Exit(run_loop(settings, console))
    try:
        print_result(run_backup_once(settings, console), console)
    except (BackupError, psycopg.Error, BotoCoreError, ClientError, OSError) as exc:
        first = (str(exc).strip().splitlines() or [type(exc).__name__])[0][:400]
        raise _fail(f"Backup failed ({type(exc).__name__}): {first}") from None


@app.command()
def attack(
    yes: Annotated[bool, typer.Option("--yes", help="Skip typing the confirmation word")] = False,
) -> None:
    """SIMULATED ransomware against the local lab database only (never real data)."""
    import psycopg
    from botocore.exceptions import BotoCoreError, ClientError

    from lab.attack import AttackError, run_attack
    from lab.config import Settings
    from lab.guard import CONFIRM_WORD, GuardError, check_attack, require_attack_allowed

    settings = Settings.load()
    # Refuse on the environment first, before asking the user anything.
    early = check_attack(
        lab_mode=settings.lab_mode, host=settings.pg_host, db=settings.pg_db, yes=True
    )
    if early:
        raise _fail("Refusing to attack: " + "; ".join(early))
    confirmation = None if yes else typer.prompt(f"Type {CONFIRM_WORD} to run the simulated attack")
    try:
        require_attack_allowed(settings, confirmation=confirmation, yes=yes)
        run_attack(settings, console, confirmation=confirmation, yes=yes)
    except GuardError as exc:
        raise _fail(f"Refusing to attack: {exc}") from None
    except AttackError as exc:
        raise _fail(str(exc)) from None
    except psycopg.Error as exc:
        raise _db_unreachable(settings, exc) from None
    except (BotoCoreError, ClientError) as exc:
        raise _fail(f"Vault error: {type(exc).__name__}: {exc}") from None


@app.command()
def detect(
    interval: Annotated[float, typer.Option(help="Seconds between health checks")] = 5.0,
    timeout: Annotated[float, typer.Option(help="Give up after this many seconds (0 = never)")] = 0,
) -> None:
    """Watch production health; print a red INCIDENT line the first time it is suspect."""
    from lab.config import Settings
    from lab.detect import run_detect

    code = run_detect(Settings.load(), console, interval=interval, timeout=timeout)
    if code:
        raise typer.Exit(code)


@app.command()
def restore(
    before: Annotated[
        str,
        typer.Option(
            help="Only use backups that started before this ISO time, e.g. 2026-11-13T00:28:00Z"
        ),
    ] = "",
) -> None:
    """Restore the newest trustworthy backup into the clean-room database and verify it."""
    import psycopg
    from botocore.exceptions import BotoCoreError, ClientError

    from lab.config import Settings
    from lab.manifest import parse_iso
    from lab.restore import run_restore
    from lab.restore_plan import RestoreRejected

    try:
        cutoff = parse_iso(before) if before else None
    except ValueError:
        raise _fail("--before must be an ISO time with a zone, e.g. 2026-11-13T00:28:00Z") from None
    settings = Settings.load()
    try:
        code = run_restore(settings, console, before=cutoff)
    except RestoreRejected as exc:
        raise _fail(f"Restore refused: {exc}") from None
    except psycopg.Error as exc:
        raise _db_unreachable(settings, exc) from None
    except (BotoCoreError, ClientError) as exc:
        raise _fail(f"Vault error: {type(exc).__name__}: {exc}") from None
    if code:
        raise typer.Exit(code)


@app.command()
def report() -> None:
    """Write RESULTS.md and docs/img/timeline.png from the last run's timeline."""
    from datetime import UTC, datetime

    from lab import timeline
    from lab.chart import render_timeline_png
    from lab.metrics import MetricsError, compute_metrics, fmt_duration, render_results_md

    data = timeline.read()
    try:
        metrics = compute_metrics(data)
    except MetricsError as exc:
        raise _fail(f"Cannot build the report: {exc}") from None
    results, chart = ROOT / "RESULTS.md", ROOT / "docs" / "img" / "timeline.png"
    results.write_text(render_results_md(metrics, data, datetime.now(UTC)), encoding="utf-8")
    render_timeline_png(metrics, chart)
    table = Table(title="Recovery results (this run)")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    for name, value in (
        ("RPO", fmt_duration(metrics.rpo_s)),
        ("Orders lost", str(metrics.orders_lost)),
        ("Detection delay", fmt_duration(metrics.detection_delay_s)),
        ("Restore time", fmt_duration(metrics.restore_s)),
        ("RTO", fmt_duration(metrics.rto_s)),
        ("Total downtime", fmt_duration(metrics.downtime_s)),
    ):
        table.add_row(name, value)
    console.print(table)
    console.print(f"Wrote {results.name} and {chart.relative_to(ROOT)}")


@app.command()
def demo() -> None:
    """Run the whole story end to end: attack, detection, restore, report (about 3 minutes)."""
    from lab.config import Settings
    from lab.demo import run_demo

    _preflight()
    code = run_demo(Settings.load(), console)
    if code:
        raise typer.Exit(code)


@app.command()
def backups() -> None:
    """List the backups in the vault, newest first, with tag and lock details (read-only)."""
    from botocore.exceptions import BotoCoreError, ClientError

    from lab.catalog import list_backups, print_catalog
    from lab.config import Settings
    from lab.storage import make_client

    settings = Settings.load()
    try:
        entries = list_backups(make_client(settings, "writer"), settings.s3_bucket)
    except (BotoCoreError, ClientError) as exc:
        raise _fail(f"Cannot list the vault: {type(exc).__name__}: {exc}") from None
    print_catalog(entries, console)


@app.command()
def health(
    restore: Annotated[
        bool, typer.Option("--restore", help="Check the clean-room restore database instead")
    ] = False,
    baseline: Annotated[
        str, typer.Option(help="Manifest JSON whose row_counts are the baseline")
    ] = "",
) -> None:
    """Check a database's content health: 'clean' or 'suspect' with reasons (exit 1 if suspect)."""
    import psycopg

    from lab.config import Settings
    from lab.db import connect
    from lab.health import check_database, load_baseline, print_health

    settings = Settings.load()
    try:
        counts = load_baseline(baseline) if baseline else None
    except (OSError, ValueError) as exc:
        raise _fail(f"Cannot read baseline: {exc}") from None
    try:
        with connect(settings, restore=restore) as conn:
            report = check_database(conn, counts)
    except psycopg.Error as exc:
        raise _db_unreachable(settings, exc) from None
    print_health(report, console, "restore database" if restore else "production database")
    if not report.is_clean:
        raise typer.Exit(1)


@app.command()
def down(
    wipe: Annotated[bool, typer.Option("--wipe", help="Also delete volumes (ALL data)")] = False,
) -> None:
    """Stop the stack. With --wipe, also delete volumes (the lab's reset path)."""
    args = ["down", "--remove-orphans"] + (["-v"] if wipe else [])
    if _compose(*args).returncode != 0:
        raise typer.Exit(1)
    console.print("[green]Stack stopped" + (" and volumes wiped." if wipe else ".") + "[/green]")


if __name__ == "__main__":
    app()
