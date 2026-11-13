import json
from datetime import UTC, datetime, timedelta, timezone

import pytest

from lab.manifest import (
    REQUIRED_FIELDS,
    build_manifest,
    checksum_sql,
    dump_key,
    dumps_manifest,
    iso_z,
    manifest_key,
    parse_iso,
    parse_manifest,
    sha256_bytes,
    sha256_file,
)
from lab.vault_rules import retention_until

START = datetime(2026, 11, 12, 23, 1, 2, 123456, tzinfo=UTC)


def make(**overrides):
    args = dict(
        key=dump_key(START),
        version_id="v1",
        started_at=START,
        completed_at=START + timedelta(seconds=3),
        sha256="ab" * 32,
        size_bytes=1234,
        row_counts={"customers": 5000, "orders": 50000},
        checksums={"customers": "c0ffee"},
        max_order_id=50000,
        health_status="clean",
        health_reasons=[],
        retain_until=retention_until(START, 10),
    )
    args.update(overrides)
    return build_manifest(**args)


def test_sha256_matches_known_value_for_bytes_and_files(tmp_path):
    expected = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    assert sha256_bytes(b"abc") == expected
    path = tmp_path / "x.dump"
    path.write_bytes(b"abc")
    assert sha256_file(path) == expected


def test_sha256_of_a_file_larger_than_one_chunk(tmp_path):
    data = b"x" * (2 * 1024 * 1024 + 5)
    path = tmp_path / "big.dump"
    path.write_bytes(data)
    assert sha256_file(path) == sha256_bytes(data)


def test_dump_key_layout_uses_utc_date_folders():
    assert dump_key(START) == "backups/2026/11/12/backup-20261112T230102Z.dump"


def test_dump_key_converts_other_timezones_to_utc():
    local = START.astimezone(timezone(timedelta(hours=-5)))
    assert dump_key(local) == dump_key(START)
    late = datetime(2026, 11, 12, 23, 30, tzinfo=timezone(timedelta(hours=-5)))
    assert dump_key(late).startswith("backups/2026/11/13/")


def test_manifest_key_is_a_sibling_of_the_dump():
    assert manifest_key("backups/2026/11/12/backup-x.dump") == (
        "backups/2026/11/12/backup-x.manifest.json"
    )
    with pytest.raises(ValueError):
        manifest_key("backups/readme.txt")


def test_iso_round_trip_and_z_suffix():
    text = iso_z(START)
    assert text == "2026-11-12T23:01:02.123456Z"
    assert parse_iso(text) == START
    assert parse_iso("2026-11-12T18:01:02-05:00") == datetime(2026, 11, 12, 23, 1, 2, tzinfo=UTC)


def test_iso_rejects_naive_datetimes():
    with pytest.raises(ValueError):
        iso_z(datetime(2026, 1, 1))
    with pytest.raises(ValueError):
        parse_iso("2026-01-01T00:00:00")


def test_manifest_has_every_required_field_and_round_trips():
    manifest = make()
    assert all(name in manifest for name in REQUIRED_FIELDS)
    assert parse_manifest(dumps_manifest(manifest)) == manifest


def test_manifest_records_retention_ten_minutes_after_start():
    manifest = make()
    assert parse_iso(manifest["retain_until"]) - START == timedelta(minutes=10)
    assert manifest["retention_mode"] == "COMPLIANCE"


def test_manifest_records_health_reasons():
    manifest = make(
        health_status="suspect", health_reasons=["ransom note table README_RANSOM exists"]
    )
    assert manifest["health"] == {
        "status": "suspect",
        "reasons": ["ransom note table README_RANSOM exists"],
    }


def test_dumps_is_stable_and_sorted():
    manifest = make()
    assert dumps_manifest(manifest) == dumps_manifest(dict(reversed(list(manifest.items()))))
    assert list(json.loads(dumps_manifest(manifest))) == sorted(manifest)


def test_parse_manifest_rejects_bad_input():
    with pytest.raises(ValueError, match="not valid JSON"):
        parse_manifest("{nope")
    with pytest.raises(ValueError, match="JSON object"):
        parse_manifest("[1]")
    broken = make()
    del broken["sha256"]
    with pytest.raises(ValueError, match="sha256"):
        parse_manifest(json.dumps(broken))
    odd = make()
    odd["health"] = {"status": "great", "reasons": []}
    with pytest.raises(ValueError, match="health"):
        parse_manifest(json.dumps(odd))


def test_checksum_sql_is_ordered_and_only_for_known_tables():
    sql = checksum_sql("orders")
    assert "ORDER BY id" in sql and "FROM orders" in sql
    with pytest.raises(ValueError):
        checksum_sql("orders; DROP TABLE orders")
