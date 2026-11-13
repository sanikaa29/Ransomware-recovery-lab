import sys
from datetime import UTC, datetime, timedelta

import pytest

from lab.catalog import CatalogEntry
from lab.demo import (
    Background,
    child_env,
    count_clean_since,
    detect_line_wanted,
    lab_command,
    run_step,
    strip_ansi,
)
from lab.manifest import build_manifest, dump_key

T0 = datetime(2026, 11, 13, 0, 0, tzinfo=UTC)


class FakeConsole:
    def __init__(self):
        import io

        self.file = io.StringIO()


def test_strip_ansi_removes_colour_codes_only():
    assert strip_ansi("\x1b[1;31mINCIDENT\x1b[0m at 00:34") == "INCIDENT at 00:34"
    assert strip_ansi("plain [text]") == "plain [text]"


def test_lab_command_runs_the_cli_with_the_same_python():
    assert lab_command("backup", "--loop") == [sys.executable, "-m", "lab.cli", "backup", "--loop"]


def test_child_env_forces_colour_and_the_fast_interval_and_clamps_width():
    env = child_env(300)
    assert env["FORCE_COLOR"] == "1" and env["BACKUP_INTERVAL_SECONDS"] == "15"
    assert env["COLUMNS"] == "120" and child_env(40)["COLUMNS"] == "80"


def test_only_the_interesting_detect_lines_are_shown():
    assert detect_line_wanted("\x1b[2m00:34:26Z health clean\x1b[0m\n") is False
    assert detect_line_wanted(" INCIDENT  00:34:52Z database health is SUSPECT") is True
    assert detect_line_wanted("\x1b[31m  - ransom note table README_RANSOM exists\x1b[0m") is True
    assert detect_line_wanted("Watching shopdb every 5s. Ctrl+C to stop.") is True


def entry(minute, health="clean"):
    started = T0 + timedelta(minutes=minute)
    manifest = build_manifest(
        key=dump_key(started), version_id="v", started_at=started, completed_at=started,
        sha256="0" * 64, size_bytes=1, row_counts={}, checksums={}, max_order_id=1,
        health_status=health, health_reasons=[], retain_until=started,
    )  # fmt: skip
    return CatalogEntry(f"m{minute}", "v", manifest, health, "COMPLIANCE", None)


def test_only_clean_backups_taken_since_the_demo_started_are_counted():
    entries = [
        entry(-30),
        entry(1),
        entry(2, "suspect"),
        entry(3),
        CatalogEntry("x", "v", None, None, None, None),
    ]
    assert count_clean_since(entries, T0) == 2
    assert count_clean_since(entries, T0 + timedelta(minutes=4)) == 0


def test_run_step_shows_output_logs_it_without_colour_and_returns_the_exit_code(tmp_path):
    console = FakeConsole()
    code = run_step(
        "demo-step",
        [sys.executable, "-c", "print('\\x1b[32mhello\\x1b[0m'); raise SystemExit(3)"],
        console, {}, tmp_path,
    )  # fmt: skip
    assert code == 3
    assert "hello" in console.file.getvalue()
    assert (tmp_path / "demo-step.log").read_text() == "hello\n"


def test_background_process_is_stopped_even_if_it_never_exits(tmp_path):
    console = FakeConsole()
    proc = Background(
        "sleeper", [sys.executable, "-c", "import time; print('up', flush=True); time.sleep(300)"],
        {}, console, show=lambda line: True, log_dir=tmp_path,
    )  # fmt: skip
    proc.start()
    assert proc.wait(timeout=0.2) is None and proc.running()
    proc.stop(timeout=5)
    assert not proc.running()
    assert (tmp_path / "sleeper.log").read_text().startswith("up")


def test_background_wait_returns_the_exit_code_when_it_finishes(tmp_path):
    proc = Background(
        "quick", [sys.executable, "-c", "raise SystemExit(0)"], {}, FakeConsole(), log_dir=tmp_path
    )
    proc.start()
    assert proc.wait(timeout=10) == 0
    proc.stop()


def test_chart_file_is_a_real_png(tmp_path):
    pytest.importorskip("matplotlib")
    from lab.chart import render_timeline_png
    from lab.metrics import compute_metrics

    data = {
        "restored_dump_started_at": "2026-11-13T00:33:57Z", "attack_start": "2026-11-13T00:34:47Z",
        "incident_detected": "2026-11-13T00:34:52Z", "restore_start": "2026-11-13T00:34:53Z",
        "restore_verified": "2026-11-13T00:34:54Z", "max_order_id_at_attack_start": 5,
        "restored_max_order_id": 5,
    }  # fmt: skip
    path = tmp_path / "img" / "timeline.png"
    render_timeline_png(compute_metrics(data), path)
    assert path.read_bytes()[:8] == b"\x89PNG\r\n\x1a\n"
