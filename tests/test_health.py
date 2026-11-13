import json

import pytest

from lab.health import EMAIL_RE, evaluate, load_baseline

GOOD_COUNTS = {"customers": 1000, "products": 200, "orders": 5000, "order_items": 15000}


def run(**overrides):
    args = {
        "email_total": 1000,
        "email_valid": 1000,
        "ransom_table_exists": False,
        "row_counts": dict(GOOD_COUNTS),
        "baseline": None,
    }
    args.update(overrides)
    return evaluate(**args)


@pytest.mark.parametrize(
    "email",
    ["a@b.com", "first.last+tag@sub.example.co.uk", "x_y%z@mail-host.io", "U1@gmail.com"],
)
def test_email_regex_accepts_normal_addresses(email):
    assert EMAIL_RE.match(email)


@pytest.mark.parametrize(
    "value",
    ["", "no-at-sign", "a@b", "a@@b.com", "gAAAAABk_encrypted-looking-token==", "a b@c.com"],
)
def test_email_regex_rejects_garbage_and_encrypted_values(value):
    assert not EMAIL_RE.match(value)


def test_clean_database():
    report = run()
    assert report.status == "clean"
    assert report.is_clean
    assert report.reasons == ()


def test_email_threshold_is_exactly_99_percent():
    assert run(email_valid=990).status == "clean"  # exactly 99%: passes
    report = run(email_valid=989)  # 98.9%: fails
    assert report.status == "suspect"
    assert "98.90%" in report.reasons[0]


def test_all_emails_encrypted_is_suspect():
    assert run(email_valid=0).status == "suspect"


def test_ransom_table_is_suspect_even_if_data_looks_fine():
    report = run(ransom_table_exists=True)
    assert report.status == "suspect"
    assert "README_RANSOM" in report.reasons[0]


def test_empty_or_missing_customers_is_suspect():
    assert "empty" in run(email_total=0, email_valid=0).reasons[0]
    assert "missing" in run(email_total=None, email_valid=0).reasons[0]


def test_row_drop_boundary_is_exactly_5_percent():
    baseline = {"orders": 1000}
    assert run(row_counts={"orders": 950}, baseline=baseline).status == "clean"  # exactly 5%
    report = run(row_counts={"orders": 949}, baseline=baseline)  # 5.1% drop
    assert report.status == "suspect"
    assert "orders rows fell from 1000 to 949" in report.reasons[0]


def test_growth_and_no_baseline_never_trigger_the_drop_rule():
    assert run(row_counts={"orders": 9999}, baseline={"orders": 1000}).status == "clean"
    assert run(row_counts={"orders": 0}, baseline=None).status == "clean"
    assert run(row_counts={"orders": 0}, baseline={}).status == "clean"


def test_missing_table_versus_baseline_is_suspect():
    report = run(row_counts={"orders": None}, baseline={"orders": 10})
    assert report.status == "suspect"
    assert "missing" in report.reasons[0]


def test_baseline_with_zero_rows_is_ignored():
    assert run(row_counts={"orders": 0}, baseline={"orders": 0}).status == "clean"


def test_multiple_problems_are_all_reported():
    report = run(
        email_valid=0,
        ransom_table_exists=True,
        row_counts={"orders": 1},
        baseline={"orders": 100},
    )
    assert len(report.reasons) == 3


def test_load_baseline_reads_manifest_row_counts(tmp_path):
    path = tmp_path / "m.json"
    path.write_text(json.dumps({"row_counts": {"orders": 5}, "other": "ignored"}))
    assert load_baseline(path) == {"orders": 5}


@pytest.mark.parametrize("content", ["[]", "{}", '{"row_counts": {"orders": "5"}}'])
def test_load_baseline_rejects_bad_manifests(tmp_path, content):
    path = tmp_path / "m.json"
    path.write_text(content)
    with pytest.raises(ValueError, match="row_counts"):
        load_baseline(path)
