"""Simulated shop traffic: one new order (1 to 3 items) about every second, until stopped.

This steady writing is what makes data loss (RPO) measurable. The latest order id is logged
every 10 seconds to ``.lab/app_sim.log``.
"""

from __future__ import annotations

import random
import signal
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from decimal import Decimal
from pathlib import Path
from typing import Any

from lab.config import LAB_DIR, Settings

LOG_PATH = LAB_DIR / "app_sim.log"
LOG_EVERY_SECONDS = 10.0
RETRY_DELAY_SECONDS = 2.0


class NotSeededError(RuntimeError):
    """The shop has no customers or products yet."""


@dataclass(frozen=True)
class OrderPlan:
    customer_id: int
    items: tuple[tuple[int, int, Decimal], ...]  # (product_id, qty, unit price)

    @property
    def total(self) -> Decimal:
        return sum((price * qty for _, qty, price in self.items), Decimal("0.00"))


def plan_order(
    rng: random.Random, max_customer_id: int, products: Sequence[tuple[int, Decimal]]
) -> OrderPlan:
    """Pick a customer and 1 to 3 distinct products. Pure, so it is unit-tested."""
    picked = rng.sample(list(products), min(rng.randint(1, 3), len(products)))
    items = tuple((pid, rng.randint(1, 3), price) for pid, price in picked)
    return OrderPlan(rng.randint(1, max_customer_id), items)


def format_log_line(now: datetime, order_id: int | None, inserted: int) -> str:
    stamp = now.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    return f"{stamp} latest_order_id={order_id} inserted_since_start={inserted}"


def load_reference(conn: Any) -> tuple[int, list[tuple[int, Decimal]]]:
    """Highest customer id and the product list, read once at start."""
    row = conn.execute("SELECT max(id) FROM customers").fetchone()
    products = [(r[0], r[1]) for r in conn.execute("SELECT id, price FROM products")]
    if not row or row[0] is None or not products:
        raise NotSeededError("no customers or products: run `lab seed` first")
    return row[0], products


def insert_order(conn: Any, plan: OrderPlan) -> int:
    """Insert one order and its items in a single transaction; returns the new order id."""
    with conn.transaction():
        row = conn.execute(
            "INSERT INTO orders (customer_id, status, total, notes) "
            "VALUES (%s, 'pending', %s, %s) RETURNING id",
            (plan.customer_id, plan.total, "simulated order"),
        ).fetchone()
        order_id = row[0]
        with conn.cursor() as cur:
            cur.executemany(
                "INSERT INTO order_items (order_id, product_id, qty, price) "
                "VALUES (%s, %s, %s, %s)",
                [(order_id, pid, qty, price) for pid, qty, price in plan.items],
            )
    return order_id


def run(
    settings: Settings,
    *,
    interval: float = 1.0,
    log_path: Path = LOG_PATH,
    stop: threading.Event | None = None,
    console: Any = None,
) -> int:
    """Insert orders until stopped (Ctrl+C or SIGTERM). Returns a process exit code."""
    import psycopg

    from lab.db import connect

    stop = stop or threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    log_path.parent.mkdir(parents=True, exist_ok=True)
    rng = random.Random()

    def say(text: str, handle: Any) -> None:
        handle.write(text + "\n")
        if console is not None:
            console.print(text, markup=False)

    conn: Any = None
    reference: tuple[int, list[tuple[int, Decimal]]] | None = None
    inserted, last_id = 0, None
    next_tick = next_log = time.monotonic()
    with log_path.open("a", buffering=1, encoding="utf-8") as log:
        say(f"{format_log_line(datetime.now(UTC), None, 0)} started", log)
        while not stop.is_set():
            try:
                if conn is None:
                    conn = connect(settings, autocommit=True)
                    reference = load_reference(conn)
                assert reference is not None
                last_id = insert_order(conn, plan_order(rng, *reference))
                inserted += 1
            except NotSeededError as exc:
                say(f"error: {exc}", log)
                return 1
            except psycopg.errors.UndefinedTable:
                say("error: tables do not exist: run `lab seed` first", log)
                return 1
            except psycopg.Error as exc:
                say(f"{type(exc).__name__}: will retry in {RETRY_DELAY_SECONDS:.0f}s", log)
                if conn is not None:
                    conn.close()
                conn = None
                stop.wait(RETRY_DELAY_SECONDS)
                next_tick = time.monotonic()
                continue
            now = time.monotonic()
            if now >= next_log:
                say(format_log_line(datetime.now(UTC), last_id, inserted), log)
                next_log = now + LOG_EVERY_SECONDS
            next_tick = max(next_tick + interval, now)  # never try to "catch up" after a stall
            stop.wait(max(0.0, next_tick - time.monotonic()))
        say(f"{format_log_line(datetime.now(UTC), last_id, inserted)} stopped", log)
    if conn is not None:
        conn.close()
    return 0
