"""``lab demo``: the whole story in one command, every step a subprocess with its own log.

up -> lockcheck -> seed -> (app-sim + backup loop) -> warm-up -> detect -> attack -> restore
-> report. Background processes are always stopped, including on Ctrl+C. Children share one
environment with a faster backup interval (15 s) so the demo fits in about three minutes.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, Any

from lab.catalog import CatalogEntry
from lab.config import LAB_DIR, ROOT, Settings

LOG_DIR = LAB_DIR / "logs"
DEMO_BACKUP_INTERVAL = 15
WARMUP_CLEAN_BACKUPS = 3
WARMUP_TIMEOUT = 150
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def lab_command(*args: str) -> list[str]:
    return [sys.executable, "-m", "lab.cli", *args]


def child_env(width: int) -> dict[str, str]:
    """Colour on (children are piped), a sane width, and the faster demo backup interval."""
    return {
        **os.environ,
        "FORCE_COLOR": "1",
        "COLUMNS": str(max(80, min(width, 120))),
        "PYTHONUNBUFFERED": "1",
        "BACKUP_INTERVAL_SECONDS": str(DEMO_BACKUP_INTERVAL),
    }


def detect_line_wanted(line: str) -> bool:
    """Of detect's output, show only the start line, the INCIDENT line and its reasons."""
    text = strip_ansi(line)
    return "INCIDENT" in text or text.startswith(("  - ", "Watching"))


def count_clean_since(entries: list[CatalogEntry], since: datetime) -> int:
    return sum(
        1
        for e in entries
        if e.manifest is not None
        and e.manifest["health"]["status"] == "clean"
        and e.started is not None
        and e.started >= since
    )


def _pump(stream: IO[str], log: IO[str], out: IO[str] | None, show: Callable[[str], bool]) -> None:
    for line in stream:
        log.write(strip_ansi(line))
        log.flush()
        if out is not None and show(line):
            out.write(line)
            out.flush()


def run_step(
    name: str, command: list[str], console: Any, env: dict[str, str], log_dir: Path = LOG_DIR
) -> int:
    """Run to completion, showing the output live and saving it (without colour codes)."""
    log_dir.mkdir(parents=True, exist_ok=True)
    with open(log_dir / f"{name}.log", "w", encoding="utf-8") as log:
        proc = subprocess.Popen(
            command, cwd=ROOT, env=env, text=True, bufsize=1,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )  # fmt: skip
        try:
            assert proc.stdout is not None
            _pump(proc.stdout, log, console.file, lambda _line: True)
            return proc.wait()
        except BaseException:
            proc.terminate()
            raise


class Background:
    """A long-running child (app-sim, backup loop, detect) that is always stopped at the end."""

    def __init__(
        self,
        name: str,
        command: list[str],
        env: dict[str, str],
        console: Any,
        *,
        show: Callable[[str], bool] | None = None,
        log_dir: Path = LOG_DIR,
    ) -> None:
        self.name, self.command, self.env = name, command, env
        self.console, self.show, self.log_dir = console, show, log_dir
        self.proc: subprocess.Popen[str] | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.proc = subprocess.Popen(
            self.command, cwd=ROOT, env=self.env, text=True, bufsize=1,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        )  # fmt: skip
        log = open(self.log_dir / f"{self.name}.log", "w", encoding="utf-8")  # noqa: SIM115
        assert self.proc.stdout is not None
        out = self.console.file if self.show else None
        self._thread = threading.Thread(
            target=self._run, args=(self.proc.stdout, log, out), daemon=True
        )
        self._thread.start()

    def _run(self, stream: IO[str], log: IO[str], out: IO[str] | None) -> None:
        try:
            _pump(stream, log, out, self.show or (lambda _line: False))
        finally:
            log.close()

    def running(self) -> bool:
        return self.proc is not None and self.proc.poll() is None

    def wait(self, timeout: float) -> int | None:
        """Exit code, or None if it is still running after ``timeout`` seconds."""
        if self.proc is None:
            return None
        try:
            return self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None

    def stop(self, timeout: float = 10) -> None:
        if self.proc is not None and self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()
        if self._thread is not None:
            self._thread.join(timeout=2)


def wait_for_clean_backups(
    settings: Settings, console: Any, since: datetime, wanted: int, timeout: float
) -> bool:
    from lab.catalog import list_backups
    from lab.storage import make_client

    client = make_client(settings, "writer")
    deadline = time.monotonic() + timeout
    seen = -1
    while time.monotonic() < deadline:
        count = count_clean_since(list_backups(client, settings.s3_bucket), since)
        if count != seen:
            console.print(f"  clean backups taken in this demo: {count}/{wanted}")
            seen = count
        if count >= wanted:
            return True
        time.sleep(3)
    return False


def _step(console: Any, number: int, title: str) -> None:
    console.rule(f"[bold]{number}. {title}")


def run_demo(settings: Settings, console: Any) -> int:
    """Run the whole story. Returns 0 only if a verified restore and the report both happened."""
    env = child_env(console.width)
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    for old in LOG_DIR.glob("*.log"):
        old.unlink()
    background: list[Background] = []
    console.print(
        f"[bold]Ransomware recovery lab demo[/bold] (local, simulated). "
        f"Backups every {DEMO_BACKUP_INTERVAL}s for the demo. Logs: {LOG_DIR}"
    )
    try:
        for number, (name, title) in enumerate(
            (("up", "Start the lab"), ("lockcheck", "Prove the vault enforces Object Lock"),
             ("seed", "Load the shop's data")),
            start=1,
        ):  # fmt: skip
            _step(console, number, title)
            if run_step(name, lab_command(name), console, env):
                return _failed(console, name)
        _step(console, 4, "Shop traffic and continuous backups")
        since = datetime.now(UTC)
        for name, args in (("app-sim", ["app-sim"]), ("backup-loop", ["backup", "--loop"])):
            proc = Background(
                name, lab_command(*args), env, console,
                show=(lambda _l: True) if name == "backup-loop" else None,
            )  # fmt: skip
            proc.start()
            background.append(proc)
        if not wait_for_clean_backups(
            settings, console, since, WARMUP_CLEAN_BACKUPS, WARMUP_TIMEOUT
        ):
            return _failed(console, "warm-up (not enough clean backups)")
        _step(console, 5, "Start watching for trouble")
        detector = Background(
            "detect", lab_command("detect"), env, console, show=detect_line_wanted
        )
        detector.start()
        background.append(detector)
        time.sleep(7)
        _step(console, 6, "Ransomware strikes (simulation)")
        if run_step("attack", lab_command("attack", "--yes"), console, env):
            return _failed(console, "attack")
        if detector.wait(timeout=60) != 0:
            return _failed(console, "detect (no incident reported)")
        _step(console, 7, "Restore the last clean backup into the clean room")
        if run_step("restore", lab_command("restore"), console, env):
            return _failed(console, "restore")
        for proc in background:
            proc.stop()
        _step(console, 8, "Report")
        if run_step("report", lab_command("report"), console, env):
            return _failed(console, "report")
        console.print(
            "\n[bold green]Demo complete.[/bold green] Open RESULTS.md and docs/img/timeline.png."
        )
        return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Interrupted: stopping background processes.[/yellow]")
        return 130
    finally:
        for proc in background:
            proc.stop()


def _failed(console: Any, what: str) -> int:
    console.print(f"[bold red]Demo stopped:[/bold red] {what} failed. See {LOG_DIR}/")
    return 1
