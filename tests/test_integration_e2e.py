"""Backup, attack and restore against the REAL stack (`make up` first).

Run with: .venv/bin/pytest -m integration

It replaces the data in shopdb with a small data set, runs a real simulated attack on it and
restores into shopdb_restored. It also overwrites .lab/timeline.json; the original is put back
afterwards. Run `lab seed` afterwards to get the full data set back.
"""

import io
from datetime import UTC, datetime

import pytest

pytestmark = pytest.mark.integration


@pytest.fixture
def stack():
    import psycopg
    from rich.console import Console

    from lab.config import LAST_CLEAN_PATH, Settings
    from lab.db import connect
    from lab.timeline import TIMELINE_PATH

    settings = Settings.load()
    try:
        connect(settings).close()
    except psycopg.Error:
        pytest.skip("stack is not running (make up)")
    saved = TIMELINE_PATH.read_bytes() if TIMELINE_PATH.is_file() else None
    LAST_CLEAN_PATH.unlink(missing_ok=True)
    yield settings, Console(file=io.StringIO(), width=200)
    if saved is None:
        TIMELINE_PATH.unlink(missing_ok=True)
    else:
        TIMELINE_PATH.write_bytes(saved)
    LAST_CLEAN_PATH.unlink(missing_ok=True)


def test_backup_attack_restore_end_to_end(stack):
    from lab import timeline
    from lab.attack import run_attack
    from lab.backup import run_backup_once
    from lab.catalog import list_backups, newest_first
    from lab.db import connect, max_order_id
    from lab.health import check_database
    from lab.restore import run_restore
    from lab.seed import Sizes, generate, load
    from lab.storage import make_client

    settings, console = stack
    with connect(settings) as conn:
        load(conn, generate(Sizes(customers=200, products=20, orders=2000)))
    started = datetime.now(UTC)

    clean = run_backup_once(settings, console)
    assert clean.health == "clean"

    run_attack(settings, console, yes=True)
    with connect(settings) as conn:
        assert not check_database(conn).is_clean  # production really is damaged

    data = timeline.read()
    assert data["locked_objects_surviving"] == data["locked_objects_targeted"] >= 2
    assert data["encrypted_rows"] == 200 + 2000

    newest = newest_first(list_backups(make_client(settings, "writer"), settings.s3_bucket))[0]
    assert newest.tag == "suspect" and newest.started >= started  # the poisoned backup

    assert run_restore(settings, console) == 0
    with connect(settings, restore=True) as conn:
        assert check_database(conn).is_clean
        assert max_order_id(conn) == 2000
    after = timeline.read()
    assert after["restored_backup_key"] == clean.key
    assert after["restored_max_order_id"] == 2000
