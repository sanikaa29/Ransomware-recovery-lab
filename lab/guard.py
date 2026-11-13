"""Safety checks for commands that change or destroy data. Pure, so they are unit-tested.

The attack guard is deliberately strict. The attack refuses to run unless ALL are true:
``LAB_MODE=true``, DB host is localhost/127.0.0.1, DB name is exactly ``shopdb``, and the user
typed ``ATTACK`` (or passed ``--yes``).
"""

from __future__ import annotations

from lab.config import Settings

LOCAL_HOSTS = frozenset({"localhost", "127.0.0.1"})
LAB_DB = "shopdb"


class GuardError(RuntimeError):
    """A safety check refused to let a command run."""


def check_local_lab_db(host: str, db: str) -> list[str]:
    """Reasons the target is not the local lab database (empty list means it is)."""
    problems = []
    if host not in LOCAL_HOSTS:
        problems.append(f"DB host is {host!r}, must be localhost or 127.0.0.1")
    if db != LAB_DB:
        problems.append(f"DB name is {db!r}, must be exactly {LAB_DB!r}")
    return problems


def require_local_lab_db(settings: Settings) -> None:
    problems = check_local_lab_db(settings.pg_host, settings.pg_db)
    if problems:
        raise GuardError("; ".join(problems))


CONFIRM_WORD = "ATTACK"


def check_attack(
    *,
    lab_mode: bool,
    host: str,
    db: str,
    confirmation: str | None = None,
    yes: bool = False,
) -> list[str]:
    """Every reason the attack must not run (empty list means it may).

    The confirmation is exact and case-sensitive (surrounding whitespace is ignored).
    """
    problems = []
    if not lab_mode:
        problems.append("LAB_MODE is not 'true' in .env")
    problems.extend(check_local_lab_db(host, db))
    if not yes and (confirmation or "").strip() != CONFIRM_WORD:
        problems.append(f"confirmation word {CONFIRM_WORD!r} was not typed (or pass --yes)")
    return problems


def require_attack_allowed(
    settings: Settings, *, confirmation: str | None = None, yes: bool = False
) -> None:
    problems = check_attack(
        lab_mode=settings.lab_mode,
        host=settings.pg_host,
        db=settings.pg_db,
        confirmation=confirmation,
        yes=yes,
    )
    if problems:
        raise GuardError("; ".join(problems))


def require_connected_to_lab_db(actual_db: str) -> None:
    """Second check after connecting: the server itself must say this is ``shopdb``."""
    if actual_db != LAB_DB:
        raise GuardError(f"connected database is {actual_db!r}, must be exactly {LAB_DB!r}")
