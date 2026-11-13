import random
from datetime import UTC, datetime, timedelta, timezone
from decimal import Decimal

from lab.app_sim import format_log_line, plan_order

PRODUCTS = [(i, Decimal(f"{i}.50")) for i in range(1, 11)]


def test_plan_order_picks_one_to_three_distinct_products_in_range():
    rng = random.Random(1)
    for _ in range(200):
        plan = plan_order(rng, 5000, PRODUCTS)
        ids = [pid for pid, _, _ in plan.items]
        assert 1 <= len(plan.items) <= 3
        assert len(set(ids)) == len(ids)
        assert 1 <= plan.customer_id <= 5000
        assert all(1 <= qty <= 3 for _, qty, _ in plan.items)


def test_plan_order_total_is_sum_of_quantity_times_price():
    plan = plan_order(random.Random(7), 10, PRODUCTS)
    assert plan.total == sum(qty * price for _, qty, price in plan.items)
    assert plan.total > 0


def test_plan_order_is_deterministic_for_a_seed_and_covers_all_sizes():
    assert plan_order(random.Random(3), 99, PRODUCTS) == plan_order(random.Random(3), 99, PRODUCTS)
    sizes = {len(plan_order(random.Random(s), 99, PRODUCTS).items) for s in range(100)}
    assert sizes == {1, 2, 3}


def test_plan_order_with_a_single_product_still_works():
    plan = plan_order(random.Random(0), 5, [(1, Decimal("2.00"))])
    assert len(plan.items) == 1


def test_log_line_is_utc_and_parseable():
    ny = timezone(timedelta(hours=-5))
    line = format_log_line(datetime(2026, 11, 12, 18, 0, 5, tzinfo=ny), 50123, 10)
    assert line == "2026-11-12T23:00:05Z latest_order_id=50123 inserted_since_start=10"


def test_log_line_before_the_first_insert():
    line = format_log_line(datetime(2026, 1, 1, tzinfo=UTC), None, 0)
    assert "latest_order_id=None" in line
