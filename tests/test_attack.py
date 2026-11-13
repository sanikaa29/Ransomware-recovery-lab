from datetime import UTC, datetime, timedelta

from cryptography.fernet import Fernet

from lab.attack import ENCRYPTED_COLUMNS, KEY_PATH, encrypt_values, save_key
from lab.catalog import CatalogEntry, locked_targets
from lab.health import EMAIL_RE
from lab.manifest import build_manifest, dump_key
from lab.vault_rules import describe_result

NOW = datetime(2026, 11, 13, 0, 20, tzinfo=UTC)


def test_encrypted_values_round_trip_and_are_not_valid_emails():
    fernet = Fernet(Fernet.generate_key())
    plain = ("ann@example.com", "555-0100", "1 Main St, Springfield")
    sealed = encrypt_values(fernet, plain)
    assert all(a != b for a, b in zip(plain, sealed, strict=True))
    assert not EMAIL_RE.match(sealed[0]) and "@" not in sealed[0]
    assert tuple(fernet.decrypt(v.encode()).decode() for v in sealed) == plain


def test_null_stays_null():
    assert encrypt_values(Fernet(Fernet.generate_key()), (None, "x"))[0] is None


def test_the_wrong_key_cannot_decrypt():
    sealed = encrypt_values(Fernet(Fernet.generate_key()), ("secret",))[0]
    other = Fernet(Fernet.generate_key())
    try:
        other.decrypt(sealed.encode())
    except Exception as exc:  # noqa: BLE001
        assert type(exc).__name__ == "InvalidToken"
    else:
        raise AssertionError("decrypted with the wrong key")


def test_only_the_documented_columns_are_targeted():
    assert ENCRYPTED_COLUMNS == {
        "customers": ("email", "phone", "address"),
        "orders": ("notes",),
    }


def test_key_is_saved_owner_only(tmp_path, monkeypatch):
    import lab.attack as attack

    monkeypatch.setattr(attack, "KEY_PATH", tmp_path / "attacker.key")
    attack.save_key(b"k" * 44)
    path = tmp_path / "attacker.key"
    assert path.read_bytes() == b"k" * 44
    assert (path.stat().st_mode & 0o777) == 0o600
    assert KEY_PATH.name == "attacker.key" and callable(save_key)


def test_describe_result_is_decided_by_what_survived():
    assert describe_result("blocked", True, "AccessDenied") == "BLOCKED"
    assert describe_result("blocked", True, "BucketNotEmpty") == "BLOCKED (not the lock)"
    assert describe_result("allowed", True) == "ALLOWED, DATA INTACT"
    assert describe_result("allowed", False) == "DESTROYED"
    assert describe_result("blocked", False, "AccessDenied") == "DESTROYED"
    assert describe_result("unsupported", True) == "UNSUPPORTED"
    assert describe_result("error", True) == "ERROR"


def entry(offset_min: int, locked_for_min: int | None, *, readable: bool = True) -> CatalogEntry:
    started = NOW + timedelta(minutes=offset_min)
    manifest = None
    if readable:
        manifest = build_manifest(
            key=dump_key(started), version_id="v", started_at=started, completed_at=started,
            sha256="0" * 64, size_bytes=1, row_counts={}, checksums={}, max_order_id=1,
            health_status="clean", health_reasons=[], retain_until=started,
        )  # fmt: skip
    until = None if locked_for_min is None else NOW + timedelta(minutes=locked_for_min)
    return CatalogEntry(f"k{offset_min}", "v", manifest, "clean", "COMPLIANCE", until)


def test_locked_targets_keep_only_unexpired_readable_backups_newest_first():
    expired = entry(-20, -10)
    old = entry(-5, 4)
    new = entry(-1, 9)
    no_lock = entry(-2, None)
    unreadable = entry(0, 9, readable=False)
    assert locked_targets([expired, old, no_lock, unreadable, new], NOW) == [new, old]


def test_locked_targets_respects_the_limit_and_may_be_empty():
    many = [entry(-i, 9) for i in range(1, 6)]
    assert len(locked_targets(many, NOW, limit=3)) == 3
    assert locked_targets([entry(-20, -10)], NOW) == []
