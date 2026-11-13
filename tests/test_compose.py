import json

from lab.compose import all_healthy, parse_ps


def _row(service, state="running", health="healthy", port=None):
    publishers = [{"URL": "127.0.0.1", "PublishedPort": port, "TargetPort": 1}] if port else []
    return {"Service": service, "State": state, "Health": health, "Publishers": publishers}


def _all_rows():
    return [
        _row("postgres", port=5432),
        _row("postgres_restore", port=5433),
        _row("vault", port=8333),
    ]


def test_parse_ps_handles_json_lines_and_array():
    rows = _all_rows()
    lines = "\n".join(json.dumps(r) for r in rows)
    assert parse_ps(lines) == parse_ps(json.dumps(rows))
    assert [r["service"] for r in parse_ps(lines)] == ["postgres", "postgres_restore", "vault"]


def test_parse_ps_formats_ports_and_missing_health():
    parsed = parse_ps(json.dumps([_row("vault", health="", port=8333)]))
    assert parsed[0]["ports"] == "127.0.0.1:8333"
    assert parsed[0]["health"] == "n/a"


def test_parse_ps_empty_output():
    assert parse_ps("") == []


def test_all_healthy_requires_every_service_running_and_healthy():
    assert all_healthy(parse_ps(json.dumps(_all_rows())))
    unhealthy = _all_rows()
    unhealthy[2]["Health"] = "starting"
    assert not all_healthy(parse_ps(json.dumps(unhealthy)))
    assert not all_healthy(parse_ps(json.dumps(_all_rows()[:2])))  # vault missing
    assert not all_healthy([])
