import pytest

from lab.guard import check_local_lab_db


@pytest.mark.parametrize("host", ["localhost", "127.0.0.1"])
def test_local_lab_database_is_allowed(host):
    assert check_local_lab_db(host, "shopdb") == []


@pytest.mark.parametrize("host", ["db.example.com", "10.0.0.5", "0.0.0.0", "LOCALHOST", ""])
def test_wrong_host_is_refused(host):
    problems = check_local_lab_db(host, "shopdb")
    assert len(problems) == 1
    assert "host" in problems[0]


@pytest.mark.parametrize("db", ["postgres", "shopdb_restored", "ShopDB", "shopdb ", ""])
def test_wrong_database_name_is_refused(db):
    problems = check_local_lab_db("localhost", db)
    assert len(problems) == 1
    assert "name" in problems[0]


def test_both_problems_are_reported_together():
    assert len(check_local_lab_db("prod.example.com", "customers")) == 2


# ---- attack guard -------------------------------------------------------------------------
from lab.config import Settings  # noqa: E402
from lab.guard import (  # noqa: E402
    GuardError,
    check_attack,
    require_attack_allowed,
    require_connected_to_lab_db,
)

GOOD = dict(lab_mode=True, host="127.0.0.1", db="shopdb")


def settings(**overrides) -> Settings:
    values = {
        "LAB_MODE": "true", "PG_HOST": "127.0.0.1", "PG_PORT": "5432", "PG_USER": "shop",
        "PG_DB": "shopdb", "RESTORE_PG_PORT": "5433", "RESTORE_PG_DB": "shopdb_restored",
        "S3_ENDPOINT_URL": "http://127.0.0.1:8333", "S3_REGION": "us-east-1",
        "S3_BUCKET": "lab-backups", "RETENTION_MINUTES": "10", "BACKUP_INTERVAL_SECONDS": "60",
        "PG_PASSWORD": "x", "WRITER_ACCESS_KEY": "x", "WRITER_SECRET_KEY": "x",
        "ATTACKER_ACCESS_KEY": "x", "ATTACKER_SECRET_KEY": "x",
    }  # fmt: skip
    values.update(overrides)
    return Settings.from_values(values)


def test_attack_allowed_with_typed_word_or_yes():
    assert check_attack(**GOOD, confirmation="ATTACK") == []
    assert check_attack(**GOOD, confirmation="  ATTACK\n") == []
    assert check_attack(**GOOD, yes=True) == []


@pytest.mark.parametrize("word", [None, "", "attack", "Attack", "ATTACKS", "yes", "y"])
def test_attack_refused_without_the_exact_word(word):
    problems = check_attack(**GOOD, confirmation=word)
    assert len(problems) == 1 and "ATTACK" in problems[0]


def test_attack_refused_when_lab_mode_is_not_true():
    problems = check_attack(lab_mode=False, host="localhost", db="shopdb", yes=True)
    assert problems == ["LAB_MODE is not 'true' in .env"]
    assert settings(LAB_MODE="false").lab_mode is False
    assert settings(LAB_MODE="").lab_mode is False
    assert settings(LAB_MODE="TRUE").lab_mode is True


@pytest.mark.parametrize("host", ["db.example.com", "10.0.0.5", "0.0.0.0", "LOCALHOST", ""])
def test_attack_refused_for_wrong_host_even_with_yes(host):
    problems = check_attack(lab_mode=True, host=host, db="shopdb", yes=True)
    assert len(problems) == 1 and "host" in problems[0]


@pytest.mark.parametrize("db", ["postgres", "shopdb_restored", "ShopDB", "shopdb ", ""])
def test_attack_refused_for_wrong_db_name_even_with_yes(db):
    problems = check_attack(lab_mode=True, host="localhost", db=db, yes=True)
    assert len(problems) == 1 and "name" in problems[0]


def test_attack_reports_every_problem_at_once():
    assert len(check_attack(lab_mode=False, host="prod", db="customers")) == 4


def test_require_attack_allowed_raises_for_wrong_host_and_wrong_db():
    with pytest.raises(GuardError, match="host"):
        require_attack_allowed(settings(PG_HOST="db.example.com"), yes=True)
    with pytest.raises(GuardError, match="name"):
        require_attack_allowed(settings(PG_DB="postgres"), yes=True)
    require_attack_allowed(settings(), yes=True)  # the good case does not raise


def test_run_attack_refuses_before_touching_anything(monkeypatch):
    """The guard runs first: a wrong host/db never reaches the database or the vault."""
    import lab.attack as attack

    def must_not_connect(_settings):
        raise AssertionError("connected to a database despite the guard")

    monkeypatch.setattr(attack, "_connect", must_not_connect)
    monkeypatch.setattr(attack, "save_key", must_not_connect)
    for bad in (settings(PG_HOST="db.example.com"), settings(PG_DB="postgres")):
        with pytest.raises(GuardError):
            attack.run_attack(bad, console=None, yes=True)
    with pytest.raises(GuardError, match="confirmation"):
        attack.run_attack(settings(), console=None)


def test_connected_database_must_be_shopdb():
    require_connected_to_lab_db("shopdb")
    for name in ("postgres", "shopdb_restored", ""):
        with pytest.raises(GuardError):
            require_connected_to_lab_db(name)
