from datetime import UTC, datetime, timedelta

import pytest

from lab.catalog import CatalogEntry
from lab.manifest import build_manifest, dump_key
from lab.restore_plan import (
    RestoreRejected,
    check_restore_target,
    compare_to_manifest,
    partition_candidates,
    restore_first_good,
)

T0 = datetime(2026, 11, 13, 0, 0, tzinfo=UTC)


def entry(minute, *, tag="clean", health="clean", version="v", broken=False, reasons=()):
    started = T0 + timedelta(minutes=minute)
    manifest = None
    if not broken:
        manifest = build_manifest(
            key=dump_key(started), version_id=version, started_at=started,
            completed_at=started, sha256="0" * 64, size_bytes=1,
            row_counts={"orders": 10}, checksums={"orders": "aa"}, max_order_id=10,
            health_status=health, health_reasons=list(reasons), retain_until=started,
        )  # fmt: skip
    return CatalogEntry(
        f"m{minute}", "mv", manifest, tag, "COMPLIANCE", None, "boom" if broken else ""
    )


def names(items):
    return [e.manifest_key for e in items]


def test_newest_clean_backup_is_first_and_suspect_ones_are_skipped():
    poisoned = entry(10, tag="suspect", health="suspect", reasons=["ransom note table exists"])
    good, older = entry(9), entry(5)
    candidates, skipped = partition_candidates([older, poisoned, good])
    assert names(candidates) == ["m9", "m5"]
    assert names([e for e, _ in skipped]) == ["m10"]
    assert "tagged suspect: ransom note table exists" in skipped[0][1]


def test_a_clean_tag_cannot_override_a_suspect_manifest():
    tampered = entry(10, tag="clean", health="suspect", reasons=["only 0.00% valid"])
    candidates, skipped = partition_candidates([tampered, entry(5)])
    assert names(candidates) == ["m5"]
    assert "manifest says suspect" in skipped[0][1]


def test_a_suspect_tag_is_respected_even_if_the_manifest_says_clean():
    candidates, skipped = partition_candidates([entry(10, tag="suspect"), entry(5)])
    assert names(candidates) == ["m5"] and "tagged suspect" in skipped[0][1]


def test_untagged_backup_is_decided_by_its_manifest():
    assert names(partition_candidates([entry(3, tag=None)])[0]) == ["m3"]


def test_unreadable_manifest_and_missing_version_are_skipped():
    candidates, skipped = partition_candidates(
        [entry(9, broken=True), entry(8, version=None), entry(7)]
    )
    assert names(candidates) == ["m7"]
    assert "unreadable" in skipped[0][1] or "unreadable" in skipped[1][1]
    assert any("version id" in reason for _, reason in skipped)


def test_before_is_strict_and_keeps_only_earlier_backups():
    entries = [entry(10), entry(9), entry(5)]
    cutoff = T0 + timedelta(minutes=9)
    candidates, skipped = partition_candidates(entries, before=cutoff)
    assert names(candidates) == ["m5"]
    assert {r for _, r in skipped} == {"started at or after --before"}


def test_no_candidates_when_everything_is_suspect():
    candidates, _ = partition_candidates([entry(2, tag="suspect"), entry(1, health="suspect")])
    assert candidates == []


def test_fallback_uses_the_next_backup_when_verification_fails():
    candidates = [entry(9), entry(8), entry(7)]

    def attempt(e):
        if e.manifest_key in ("m9", "m8"):
            raise RestoreRejected(f"{e.manifest_key} failed verification")
        return "restored"

    found, rejected = restore_first_good(candidates, attempt)
    assert found is not None and found[0].manifest_key == "m7" and found[1] == "restored"
    assert [(e.manifest_key, r) for e, r in rejected] == [
        ("m9", "m9 failed verification"),
        ("m8", "m8 failed verification"),
    ]


def test_first_good_candidate_stops_the_search():
    seen = []
    found, rejected = restore_first_good([entry(2), entry(1)], lambda e: seen.append(e) or "ok")
    assert found[0].manifest_key == "m2" and len(seen) == 1 and rejected == []


def test_all_rejected_returns_none_with_every_reason():
    def attempt(e):
        raise RestoreRejected("bad")

    found, rejected = restore_first_good([entry(2), entry(1)], attempt)
    assert found is None and len(rejected) == 2


def test_other_errors_are_not_swallowed():
    def attempt(e):
        raise KeyError("bug")

    with pytest.raises(KeyError):
        restore_first_good([entry(1)], attempt)


MANIFEST = {"row_counts": {"orders": 10, "customers": 3}, "checksums": {"orders": "aa"}}


def test_matching_restore_has_no_problems():
    assert compare_to_manifest(MANIFEST, {"orders": 10, "customers": 3}, {"orders": "aa"}) == []


def test_row_count_and_checksum_differences_are_reported():
    problems = compare_to_manifest(MANIFEST, {"orders": 9, "customers": None}, {"orders": "zz"})
    assert any("customers: None rows" in p for p in problems)
    assert any("orders: 9 rows restored, backup recorded 10" in p for p in problems)
    assert any("orders: checksum differs" in p for p in problems)


def test_a_missing_checksum_counts_as_a_difference():
    assert compare_to_manifest(MANIFEST, {"orders": 10, "customers": 3}, {}) != []


def test_restore_target_must_not_be_production():
    check_restore_target("shopdb_restored", 5433, "shopdb", 5432)
    with pytest.raises(RestoreRejected, match="production database"):
        check_restore_target("shopdb", 5433, "shopdb", 5432)
    with pytest.raises(RestoreRejected, match="production port"):
        check_restore_target("shopdb_restored", 5432, "shopdb", 5432)
    with pytest.raises(RestoreRejected, match="identifier"):
        check_restore_target('x"; DROP DATABASE shopdb; --', 5433, "shopdb", 5432)
