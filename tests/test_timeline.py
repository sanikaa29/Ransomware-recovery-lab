from datetime import UTC, datetime

import pytest

from lab import timeline

T = datetime(2026, 11, 13, 0, 29, 3, tzinfo=UTC)


def test_record_and_read_back(tmp_path):
    path = tmp_path / "timeline.json"
    timeline.record("attack_start", T, path)
    timeline.set_value("max_order_id_at_attack_start", 50000, path)
    data = timeline.read(path)
    assert timeline.moment(data, "attack_start") == T
    assert data["max_order_id_at_attack_start"] == 50000
    assert timeline.moment(data, "attack_end") is None


def test_later_phases_add_keys_without_losing_earlier_ones(tmp_path):
    path = tmp_path / "timeline.json"
    timeline.record("attack_start", T, path)
    timeline.record("incident_detected", T, path)
    assert set(timeline.read(path)) == {"attack_start", "incident_detected"}


def test_reset_starts_a_new_timeline(tmp_path):
    path = tmp_path / "timeline.json"
    timeline.record("attack_start", T, path)
    timeline.reset(path)
    assert timeline.read(path) == {}


def test_unknown_key_is_rejected_and_missing_file_reads_empty(tmp_path):
    path = tmp_path / "nope.json"
    assert timeline.read(path) == {}
    with pytest.raises(ValueError):
        timeline.record("lunch", T, path)
