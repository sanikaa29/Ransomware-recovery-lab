from datetime import UTC, datetime

import pytest

from lab.metrics import (
    MetricsError,
    compute_metrics,
    fmt_duration,
    render_results_md,
)

DATA = {
    "restored_dump_started_at": "2026-11-13T00:33:57.000000Z",
    "attack_start": "2026-11-13T00:34:47.500000Z",
    "incident_detected": "2026-11-13T00:34:52.000000Z",
    "restore_start": "2026-11-13T00:35:00.000000Z",
    "restore_verified": "2026-11-13T00:35:02.500000Z",
    "max_order_id_at_attack_start": 50012,
    "restored_max_order_id": 50000,
}
FACTS = {
    **DATA,
    "encrypted_rows": 55000,
    "locked_objects_targeted": 8,
    "locked_objects_surviving": 8,
    "backup_interval_seconds": 15,
    "retention_minutes": 10,
    "vault_attempts": [
        {"action": "a", "result": "BLOCKED", "code": "AccessDenied"},
        {"action": "b", "result": "ALLOWED, DATA INTACT (new version added)", "code": "-"},
    ],
}


def test_every_metric_is_computed_from_the_timeline():
    m = compute_metrics(DATA)
    assert m.rpo_s == pytest.approx(50.5)
    assert m.detection_delay_s == pytest.approx(4.5)
    assert m.response_gap_s == pytest.approx(8.0)
    assert m.restore_s == pytest.approx(2.5)
    assert m.rto_s == pytest.approx(10.5)
    assert m.downtime_s == pytest.approx(15.0)
    assert m.orders_lost == 12


def test_rto_is_response_gap_plus_restore_time_and_downtime_adds_up():
    m = compute_metrics(DATA)
    assert m.rto_s == pytest.approx(m.response_gap_s + m.restore_s)
    assert m.downtime_s == pytest.approx(m.detection_delay_s + m.rto_s)


def test_no_orders_lost_when_restored_matches_and_never_negative():
    assert compute_metrics({**DATA, "restored_max_order_id": 50012}).orders_lost == 0
    assert compute_metrics({**DATA, "restored_max_order_id": 60000}).orders_lost == 0


def test_missing_keys_name_the_command_to_run():
    partial = {k: v for k, v in DATA.items() if k != "incident_detected"}
    with pytest.raises(MetricsError, match=r"incident_detected.*lab detect"):
        compute_metrics(partial)
    with pytest.raises(MetricsError, match="lab attack"):
        compute_metrics({})


@pytest.mark.parametrize(
    ("key", "value", "message"),
    [
        ("restored_dump_started_at", "2026-11-13T00:34:48.000000Z", "after the attack"),
        ("incident_detected", "2026-11-13T00:34:00.000000Z", "before the attack"),
        ("restore_start", "2026-11-13T00:34:50.000000Z", "before the incident"),
        ("restore_verified", "2026-11-13T00:34:59.000000Z", "before it started"),
    ],
)
def test_out_of_order_timelines_are_rejected(key, value, message):
    with pytest.raises(MetricsError, match=message):
        compute_metrics({**DATA, key: value})


def test_garbage_time_is_rejected():
    with pytest.raises(MetricsError, match="not a valid time"):
        compute_metrics({**DATA, "attack_start": "yesterday"})


def test_duration_formatting():
    assert fmt_duration(0.666) == "0.7 s"
    assert fmt_duration(59.94) == "59.9 s"
    assert fmt_duration(75) == "1 m 15 s"


def test_report_shows_the_measured_numbers_and_the_caveats():
    text = render_results_md(compute_metrics(DATA), FACTS, datetime(2026, 11, 13, tzinfo=UTC))
    for expected in (
        "50.5 s",
        "4.5 s",
        "8.0 s",
        "2.5 s",
        "10.5 s",
        "15.0 s",
        "| Orders lost | 12 |",
    ):
        assert expected in text
    assert "15 s in this run" in text
    assert "tiny" in text and "one sample" in text
    assert "docs/img/timeline.png" in text
    assert "ALLOWED, DATA INTACT (new version added)" in text
