from datetime import UTC, datetime, timedelta

from lab.catalog import CatalogEntry, newest_first
from lab.manifest import build_manifest, dump_key, iso_z

T0 = datetime(2026, 11, 12, 23, 0, 0, tzinfo=UTC)


def entry(offset_s: int, tag: str | None = "clean", *, broken: bool = False) -> CatalogEntry:
    started = T0 + timedelta(seconds=offset_s)
    key = dump_key(started).replace(".dump", ".manifest.json")
    manifest = None
    if not broken:
        manifest = build_manifest(
            key=dump_key(started),
            version_id="v",
            started_at=started,
            completed_at=started,
            sha256="0" * 64,
            size_bytes=1,
            row_counts={},
            checksums={},
            max_order_id=1,
            health_status="clean",
            health_reasons=[],
            retain_until=started + timedelta(minutes=10),
        )
        assert manifest["dump_started_at"] == iso_z(started)
    return CatalogEntry(key, "v", manifest, tag, "COMPLIANCE", None, "bad" if broken else "")


def test_newest_first_orders_by_dump_start():
    a, b, c = entry(0), entry(120), entry(60)
    assert newest_first([a, b, c]) == [b, c, a]


def test_unreadable_manifests_sort_last_newest_key_first():
    old_bad, new_bad, good = entry(0, broken=True), entry(300, broken=True), entry(30)
    assert newest_first([old_bad, good, new_bad]) == [good, new_bad, old_bad]
