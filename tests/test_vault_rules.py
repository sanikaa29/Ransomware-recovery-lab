from datetime import UTC, datetime, timedelta, timezone

import pytest

from lab.vault_rules import (
    classify,
    extract_error,
    judge,
    lock_verdict,
    retention_until,
    same_instant,
    skew_seconds,
    verified_outcome,
)


class FakeClientError(Exception):
    def __init__(self, code: str, status: int) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}, "ResponseMetadata": {"HTTPStatusCode": status}}


@pytest.mark.parametrize(
    ("code", "status", "expected"),
    [
        ("AccessDenied", 403, "blocked"),
        ("InvalidRequest", 400, "blocked"),
        ("InvalidBucketState", 409, "blocked"),
        ("NotImplemented", 501, "unsupported"),
        ("NoSuchBucket", 404, "error"),  # a missing bucket is not a lock denial
        ("InternalError", 500, "error"),
        ("Whatever", 0, "error"),
    ],
)
def test_classify_only_trusts_real_denials(code, status, expected):
    assert classify(code, status) == expected


def test_extract_error_reads_botocore_style_and_plain_exceptions():
    assert extract_error(FakeClientError("AccessDenied", 403)) == ("AccessDenied", 403)
    assert extract_error(ConnectionError("boom")) == ("ConnectionError", 0)


@pytest.mark.parametrize(
    ("expected", "outcome", "code", "verdict"),
    [
        ("allow", "allowed", "-", "OK"),
        ("allow", "blocked", "AccessDenied", "MISMATCH"),
        ("deny", "blocked", "AccessDenied", "OK"),
        ("deny", "allowed", "-", "MISMATCH"),
        ("deny", "unsupported", "NotImplemented", "MISMATCH"),
        ("deny", "blocked", "BucketNotEmpty", "INFO"),  # blocked by contents, not by the lock
        ("record", "allowed", "-", "INFO"),
    ],
)
def test_judge(expected, outcome, code, verdict):
    assert judge(expected, outcome, code) == verdict


@pytest.mark.parametrize(
    ("outcome", "intact", "expected"),
    [
        ("blocked", True, "blocked"),
        ("blocked", False, "allowed"),  # error code said blocked, but the target is gone
        ("allowed", True, "allowed"),
        ("error", True, "blocked"),  # failed and the target survived
        ("allowed", False, "allowed"),
    ],
)
def test_verified_outcome_trusts_survival_over_error_codes(outcome, intact, expected):
    assert verified_outcome(outcome, intact) == expected


def test_retention_until_adds_minutes_in_utc():
    now = datetime(2026, 11, 12, 12, 0, tzinfo=timezone(timedelta(hours=-5)))
    result = retention_until(now, 10)
    assert result == datetime(2026, 11, 12, 17, 10, tzinfo=UTC)
    assert result.utcoffset() == timedelta(0)


def test_retention_until_rejects_naive_time_and_non_positive_minutes():
    with pytest.raises(ValueError, match="timezone-aware"):
        retention_until(datetime(2026, 1, 1), 5)
    with pytest.raises(ValueError, match="positive"):
        retention_until(datetime(2026, 1, 1, tzinfo=UTC), 0)


def test_skew_seconds_from_http_date():
    local = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)
    assert skew_seconds("Thu, 12 Nov 2026 12:00:07 GMT", local) == 7.0
    assert skew_seconds("Thu, 12 Nov 2026 11:59:50 GMT", local) == -10.0


def test_same_instant_tolerance():
    a = datetime(2026, 11, 12, 12, 0, 0, tzinfo=UTC)
    assert same_instant(a, a + timedelta(milliseconds=500))
    assert not same_instant(a, a + timedelta(seconds=30))


def _verdict(**overrides):
    args = {
        "lock_enabled": True,
        "mode": "COMPLIANCE",
        "intact": True,
        "retention_unchanged": True,
        "versioning_enabled": True,
    }
    args.update(overrides)
    return lock_verdict(["blocked", "blocked", "blocked"], **args)


def test_lock_verdict_passes_only_when_everything_holds():
    assert _verdict() == (True, [])


@pytest.mark.parametrize(
    "override",
    [
        {"lock_enabled": False},
        {"mode": "GOVERNANCE"},
        {"intact": False},
        {"retention_unchanged": False},
        {"versioning_enabled": False},
    ],
)
def test_lock_verdict_fails_on_any_broken_guarantee(override):
    passed, problems = _verdict(**override)
    assert not passed
    assert len(problems) == 1


def test_lock_verdict_fails_when_an_action_succeeds_or_is_unsupported():
    passed, problems = lock_verdict(
        ["blocked", "allowed", "unsupported"],
        lock_enabled=True,
        mode="COMPLIANCE",
        intact=True,
        retention_unchanged=True,
        versioning_enabled=True,
    )
    assert not passed
    assert "2 of 3" in problems[0]


def test_lock_problems_accepts_matching_compliance_retention():
    from lab.vault_rules import lock_problems

    until = datetime(2026, 11, 12, 23, 11, tzinfo=UTC)
    assert lock_problems({"Mode": "COMPLIANCE", "RetainUntilDate": until}, until) == []
    close = until + timedelta(milliseconds=400)
    assert lock_problems({"Mode": "COMPLIANCE", "RetainUntilDate": close}, until) == []


def test_lock_problems_flags_missing_wrong_mode_and_wrong_date():
    from lab.vault_rules import lock_problems

    until = datetime(2026, 11, 12, 23, 11, tzinfo=UTC)
    assert "NOT locked" in lock_problems(None, until)[0]
    assert "NOT locked" in lock_problems({}, until)[0]
    wrong_mode = lock_problems({"Mode": "GOVERNANCE", "RetainUntilDate": until}, until)
    assert "GOVERNANCE" in wrong_mode[0]
    early = until - timedelta(minutes=5)
    assert "expected" in lock_problems({"Mode": "COMPLIANCE", "RetainUntilDate": early}, until)[0]
    assert "no RetainUntilDate" in lock_problems({"Mode": "COMPLIANCE"}, until)[0]
