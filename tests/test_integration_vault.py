"""Needs the stack running (`make up`). Run with: .venv/bin/pytest -m integration"""

import pytest

pytestmark = pytest.mark.integration


def test_lockcheck_passes_against_real_vault():
    from lab.config import Settings
    from lab.lockcheck import run_lockcheck

    report = run_lockcheck(Settings.load())
    assert report.passed, report.problems


def test_no_permission_mismatches_against_real_vault():
    from lab.config import Settings
    from lab.perms import run_perms

    rows = run_perms(Settings.load())
    mismatches = [
        (r.identity, r.action, r.outcome, r.code) for r in rows if r.verdict == "MISMATCH"
    ]
    assert not mismatches, mismatches
