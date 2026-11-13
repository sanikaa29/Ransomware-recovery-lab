"""Deterministic demo data: same seed, same rows, every time.

``generate`` builds everything in memory (pure, testable); ``load`` writes it with COPY.
"""

from __future__ import annotations

import random
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any

from lab.health import RANSOM_TABLE
from lab.schema import TABLES, apply_schema

SEED = 42
BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)
STATUSES = ("pending", "paid", "shipped", "delivered", "cancelled")
MAX_ITEMS_PER_ORDER = 5
Row = tuple[Any, ...]


@dataclass(frozen=True)
class Sizes:
    customers: int = 5_000
    products: int = 200
    orders: int = 50_000


@dataclass
class Dataset:
    customers: list[Row]
    products: list[Row]
    orders: list[Row]
    order_items: list[Row]


def _slug(text: str) -> str:
    """Lowercase letters, digits and . _ - only, so the e-mail is always valid."""
    return re.sub(r"[^a-z0-9._-]", "", text.lower()) or "user"


def generate(sizes: Sizes | None = None, seed: int = SEED) -> Dataset:
    from faker import Faker  # imported here so other modules and tests do not need it

    sizes = sizes or Sizes()
    if sizes.products < MAX_ITEMS_PER_ORDER:
        raise ValueError(f"need at least {MAX_ITEMS_PER_ORDER} products")
    fake = Faker("en_US")
    fake.seed_instance(seed)
    rng = random.Random(seed)

    customers: list[Row] = []
    for i in range(1, sizes.customers + 1):
        email = f"{_slug(fake.user_name())}{i}@{_slug(fake.free_email_domain())}"
        address = fake.address().replace("\n", ", ")
        created = BASE_TIME + timedelta(minutes=i)
        customers.append((i, fake.name(), email, fake.phone_number(), address, created))

    products: list[Row] = []
    prices: dict[int, Decimal] = {}
    for i in range(1, sizes.products + 1):
        prices[i] = (Decimal(rng.randint(299, 49_999)) / 100).quantize(Decimal("0.01"))
        products.append((i, fake.catch_phrase(), prices[i]))

    notes_pool = [fake.sentence(nb_words=8) for _ in range(200)]
    orders: list[Row] = []
    order_items: list[Row] = []
    item_id = 0
    for order_id in range(1, sizes.orders + 1):
        picked = rng.sample(range(1, sizes.products + 1), rng.randint(1, MAX_ITEMS_PER_ORDER))
        total = Decimal("0.00")
        for product_id in picked:
            qty = rng.randint(1, 4)
            item_id += 1
            order_items.append((item_id, order_id, product_id, qty, prices[product_id]))
            total += prices[product_id] * qty
        orders.append(
            (
                order_id,
                rng.randint(1, sizes.customers),
                rng.choice(STATUSES),
                total,
                rng.choice(notes_pool),
                BASE_TIME + timedelta(seconds=60 * order_id),
            )
        )
    return Dataset(customers, products, orders, order_items)


def _copy(cur: Any, target: str, rows: Iterable[Row]) -> None:
    with cur.copy(f"COPY {target} FROM STDIN") as copy:
        for row in rows:
            copy.write_row(row)


def load(conn: Any, data: Dataset) -> dict[str, int]:
    """Create tables if needed, then truncate and reload. Returns row counts per table."""
    apply_schema(conn)
    with conn.cursor() as cur:
        cur.execute(f"DROP TABLE IF EXISTS {RANSOM_TABLE}")  # a previous simulated attack
        cur.execute("TRUNCATE order_items, orders, products, customers RESTART IDENTITY")
        _copy(cur, "customers (id, name, email, phone, address, created_at)", data.customers)
        _copy(cur, "products (id, name, price)", data.products)
        _copy(cur, "orders (id, customer_id, status, total, notes, created_at)", data.orders)
        _copy(cur, "order_items (id, order_id, product_id, qty, price)", data.order_items)
        # Rows were loaded with explicit ids, so move each sequence past them. app-sim then
        # continues from the next id instead of colliding.
        for table in TABLES:
            cur.execute(
                f"SELECT setval(pg_get_serial_sequence('{table}', 'id'), "
                f"(SELECT max(id) FROM {table}))"
            )
        counts = {}
        for table in TABLES:
            cur.execute(f"SELECT count(*) FROM {table}")
            counts[table] = cur.fetchone()[0]
    conn.commit()
    return counts
