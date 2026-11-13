import pytest

pytest.importorskip("faker", reason="Faker is installed by `make setup`")

from lab.health import EMAIL_RE  # noqa: E402
from lab.seed import MAX_ITEMS_PER_ORDER, Sizes, generate  # noqa: E402

SMALL = Sizes(customers=60, products=10, orders=120)


def test_sizes_and_sequential_ids():
    data = generate(SMALL)
    assert len(data.customers) == 60
    assert len(data.products) == 10
    assert len(data.orders) == 120
    assert [r[0] for r in data.customers] == list(range(1, 61))
    assert [r[0] for r in data.orders] == list(range(1, 121))
    assert [r[0] for r in data.order_items] == list(range(1, len(data.order_items) + 1))


def test_same_seed_gives_identical_data_and_other_seeds_differ():
    assert generate(SMALL) == generate(SMALL)
    assert generate(SMALL, seed=1).customers != generate(SMALL, seed=2).customers


def test_every_email_is_valid_and_unique():
    emails = [row[2] for row in generate(SMALL).customers]
    assert all(EMAIL_RE.match(e) for e in emails)
    assert len(set(emails)) == len(emails)


def test_foreign_keys_point_at_real_rows():
    data = generate(SMALL)
    customer_ids = {r[0] for r in data.customers}
    product_ids = {r[0] for r in data.products}
    order_ids = {r[0] for r in data.orders}
    assert {r[1] for r in data.orders} <= customer_ids
    assert {r[1] for r in data.order_items} <= order_ids
    assert {r[2] for r in data.order_items} <= product_ids


def test_order_total_equals_sum_of_its_items_and_item_counts_are_in_range():
    data = generate(SMALL)
    totals: dict[int, object] = {}
    counts: dict[int, int] = {}
    for _, order_id, _, qty, price in data.order_items:
        totals[order_id] = totals.get(order_id, 0) + qty * price
        counts[order_id] = counts.get(order_id, 0) + 1
    assert set(counts) == {r[0] for r in data.orders}
    assert all(1 <= n <= MAX_ITEMS_PER_ORDER for n in counts.values())
    assert all(row[3] == totals[row[0]] for row in data.orders)


def test_average_is_about_three_items_per_order():
    data = generate(Sizes(customers=50, products=10, orders=2000))
    assert 2.5 <= len(data.order_items) / len(data.orders) <= 3.5


def test_too_few_products_is_rejected():
    with pytest.raises(ValueError, match="products"):
        generate(Sizes(customers=5, products=2, orders=5))
