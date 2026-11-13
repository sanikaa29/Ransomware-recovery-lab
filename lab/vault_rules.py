"""Pure decision logic for vault checks (stdlib only, so it is unit-testable without boto3).

The key idea: an S3 error is not automatically proof that Object Lock works. A 404 (wrong
bucket), a 5xx (server trouble) or a 501 (feature not implemented) would all look like
"the delete failed". Only 400/403/409 count as a genuine block.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.utils import parsedate_to_datetime
from typing import Literal

Outcome = Literal["blocked", "allowed", "unsupported", "error"]
Expectation = Literal["allow", "deny", "record"]

BLOCKING_STATUSES = frozenset({400, 403, 409})
# Denials that happen for reasons other than the lock, so they prove nothing about it.
NOT_LOCK_RELATED = frozenset({"BucketNotEmpty"})


def classify(code: str, status: int) -> Outcome:
    """Turn an S3 error (code + HTTP status) into an outcome."""
    if status == 501 or code == "NotImplemented":
        return "unsupported"
    if status in BLOCKING_STATUSES:
        return "blocked"
    return "error"


def extract_error(exc: BaseException) -> tuple[str, int]:
    """(error code, HTTP status) from a botocore ClientError, or (type name, 0) otherwise."""
    response = getattr(exc, "response", None)
    if not isinstance(response, dict):
        return type(exc).__name__, 0
    code = str(response.get("Error", {}).get("Code") or "unknown")
    status = int(response.get("ResponseMetadata", {}).get("HTTPStatusCode") or 0)
    return code, status


def verified_outcome(outcome: Outcome, intact: bool) -> Outcome:
    """Decide by what survived, not by the error code.

    A destructive call only counts as blocked if it failed AND the target is still there.
    If the target is gone, it was destroyed no matter what the response said.
    """
    if not intact:
        return "allowed"
    return "allowed" if outcome == "allowed" else "blocked"


def judge(expected: Expectation, outcome: Outcome, code: str = "") -> str:
    """OK / MISMATCH / INFO for one permission probe."""
    if expected == "record":
        return "INFO"
    if expected == "allow":
        return "OK" if outcome == "allowed" else "MISMATCH"
    if outcome != "blocked":
        return "MISMATCH"
    return "INFO" if code in NOT_LOCK_RELATED else "OK"


def retention_until(now: datetime, minutes: int) -> datetime:
    """UTC retain-until date, ``minutes`` after ``now`` (which must be timezone-aware)."""
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if minutes <= 0:
        raise ValueError("retention minutes must be positive")
    return now.astimezone(UTC) + timedelta(minutes=minutes)


def skew_seconds(date_header: str, local_now: datetime) -> float:
    """Vault clock minus local clock, from an HTTP ``Date`` header."""
    return (parsedate_to_datetime(date_header) - local_now).total_seconds()


def same_instant(a: datetime, b: datetime, tolerance_seconds: float = 1.0) -> bool:
    return abs((a - b).total_seconds()) <= tolerance_seconds


def describe_result(outcome: Outcome, intact: bool, code: str = "") -> str:
    """Plain-language result of one destructive attempt, decided by what survived."""
    if not intact:
        return "DESTROYED"
    if outcome == "blocked":
        return "BLOCKED (not the lock)" if code in NOT_LOCK_RELATED else "BLOCKED"
    if outcome == "allowed":
        return "ALLOWED, DATA INTACT"
    return "UNSUPPORTED" if outcome == "unsupported" else "ERROR"


def lock_problems(
    retention: dict[str, object] | None, expected_until: datetime, expected_mode: str = "COMPLIANCE"
) -> list[str]:
    """Why an uploaded object's retention is not what we asked for (empty list = locked)."""
    if not retention:
        return ["object has no retention at all: it is NOT locked"]
    problems: list[str] = []
    if retention.get("Mode") != expected_mode:
        problems.append(f"retention mode is {retention.get('Mode')!r}, expected {expected_mode!r}")
    until = retention.get("RetainUntilDate")
    if not isinstance(until, datetime):
        problems.append("retention has no RetainUntilDate")
    elif not same_instant(until, expected_until):
        problems.append(
            f"retain-until is {until.isoformat()}, expected {expected_until.isoformat()}"
        )
    return problems


def lock_verdict(
    outcomes: list[Outcome],
    *,
    lock_enabled: bool,
    mode: str | None,
    intact: bool,
    retention_unchanged: bool,
    versioning_enabled: bool,
) -> tuple[bool, list[str]]:
    """PASS only if every destructive action was blocked AND the object demonstrably survived."""
    problems: list[str] = []
    if not lock_enabled:
        problems.append("bucket does not report Object Lock as enabled")
    if mode != "COMPLIANCE":
        problems.append(f"object retention mode is {mode!r}, expected 'COMPLIANCE'")
    bad = [o for o in outcomes if o != "blocked"]
    if bad:
        kinds = ", ".join(sorted(set(bad)))
        problems.append(
            f"{len(bad)} of {len(outcomes)} destructive actions not cleanly blocked ({kinds})"
        )
    if not intact:
        problems.append("locked object version is no longer retrievable")
    if not retention_unchanged:
        problems.append("retention date changed after the shorten attempt")
    if not versioning_enabled:
        problems.append("bucket versioning is no longer Enabled")
    return (not problems, problems)
