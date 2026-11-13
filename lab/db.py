"""Postgres connections for the production and clean-room restore databases."""

from __future__ import annotations

from typing import Any

import psycopg

from lab.config import Settings


def connect(
    settings: Settings,
    *,
    restore: bool = False,
    dbname: str | None = None,
    autocommit: bool = False,
) -> psycopg.Connection:
    """Connect to production (default) or, with ``restore=True``, the clean-room database."""
    port = settings.restore_pg_port if restore else settings.pg_port
    name = dbname or (settings.restore_pg_db if restore else settings.pg_db)
    return psycopg.connect(
        host=settings.pg_host,
        port=port,
        user=settings.pg_user,
        password=settings.pg_password,
        dbname=name,
        autocommit=autocommit,
        connect_timeout=5,
    )


def max_order_id(conn: Any) -> int | None:
    """Highest order id, or None when there are no orders. Used to measure lost orders."""
    row = conn.execute("SELECT max(id) FROM orders").fetchone()
    return None if row is None else row[0]
