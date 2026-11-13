"""Parse ``docker compose ps --format json`` output (stdlib only, so it is unit-testable)."""

from __future__ import annotations

import json

EXPECTED_SERVICES = frozenset({"postgres", "postgres_restore", "vault"})


def parse_ps(text: str) -> list[dict[str, str]]:
    """Normalise compose's JSON (either one JSON array or one object per line)."""
    text = text.strip()
    if not text:
        return []
    if text.startswith("["):
        rows = json.loads(text)
    else:
        rows = [json.loads(line) for line in text.splitlines() if line.strip()]
    result = []
    for row in rows:
        publishers = row.get("Publishers") or []
        ports = sorted(
            {f"{p['URL']}:{p['PublishedPort']}" for p in publishers if p.get("PublishedPort")}
        )
        result.append(
            {
                "service": str(row.get("Service", "")),
                "state": str(row.get("State", "")),
                "health": str(row.get("Health") or "n/a"),
                "ports": ", ".join(ports) or "-",
            }
        )
    return sorted(result, key=lambda r: r["service"])


def all_healthy(rows: list[dict[str, str]]) -> bool:
    """True only if every expected service is present, running, and healthy."""
    by_name = {r["service"]: r for r in rows}
    return all(
        name in by_name
        and by_name[name]["state"] == "running"
        and by_name[name]["health"] == "healthy"
        for name in EXPECTED_SERVICES
    )
