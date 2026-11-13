"""Database schema (TEXT columns, not VARCHAR(n), so encrypted values always fit)."""

from __future__ import annotations

from typing import Any

TABLES = ("customers", "products", "orders", "order_items")

SCHEMA = (
    """CREATE TABLE IF NOT EXISTS customers (
        id BIGSERIAL PRIMARY KEY,
        name TEXT,
        email TEXT,
        phone TEXT,
        address TEXT,
        created_at TIMESTAMPTZ DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS products (
        id BIGSERIAL PRIMARY KEY,
        name TEXT,
        price NUMERIC(10,2)
    )""",
    """CREATE TABLE IF NOT EXISTS orders (
        id BIGSERIAL PRIMARY KEY,
        customer_id BIGINT REFERENCES customers(id),
        status TEXT,
        total NUMERIC(10,2),
        notes TEXT,
        created_at TIMESTAMPTZ DEFAULT now()
    )""",
    """CREATE TABLE IF NOT EXISTS order_items (
        id BIGSERIAL PRIMARY KEY,
        order_id BIGINT REFERENCES orders(id),
        product_id BIGINT REFERENCES products(id),
        qty INT,
        price NUMERIC(10,2)
    )""",
)


def apply_schema(conn: Any) -> None:
    """Create the tables if they do not exist yet (safe to run repeatedly)."""
    for statement in SCHEMA:
        conn.execute(statement)
