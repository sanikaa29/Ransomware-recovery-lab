"""Configuration loaded from ``.env`` (stdlib only, so it works before deps are installed)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = ROOT / ".lab"
ENV_FILE = ROOT / ".env"
# Manifest of the newest clean backup: the health check's baseline for "did rows disappear?".
LAST_CLEAN_PATH = LAB_DIR / "last_clean_manifest.json"


class ConfigError(RuntimeError):
    """Raised when required configuration is missing or malformed."""


def parse_env(text: str) -> dict[str, str]:
    """Parse ``KEY=VALUE`` lines, ignoring blanks and ``#`` comments."""
    values: dict[str, str] = {}
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def load_env(path: Path = ENV_FILE) -> dict[str, str]:
    """Read ``.env``; real environment variables override file values."""
    values = parse_env(path.read_text(encoding="utf-8")) if path.exists() else {}
    for key in values:
        if key in os.environ:
            values[key] = os.environ[key]
    return values


def _require(values: dict[str, str], key: str) -> str:
    value = values.get(key, "")
    if not value:
        raise ConfigError(f"missing {key} in .env (run `make setup`)")
    return value


def _require_int(values: dict[str, str], key: str) -> int:
    raw = _require(values, key)
    try:
        return int(raw)
    except ValueError:
        raise ConfigError(f"{key} must be an integer") from None


@dataclass(frozen=True)
class Settings:
    """Typed view of ``.env``. Secret fields are excluded from ``repr`` so they never get logged."""

    lab_mode: bool
    pg_host: str
    pg_port: int
    pg_user: str
    pg_db: str
    restore_pg_port: int
    restore_pg_db: str
    s3_endpoint_url: str
    s3_region: str
    s3_bucket: str
    retention_minutes: int
    backup_interval_seconds: int
    pg_password: str = field(repr=False)
    writer_access_key: str = field(repr=False)
    writer_secret_key: str = field(repr=False)
    attacker_access_key: str = field(repr=False)
    attacker_secret_key: str = field(repr=False)

    @classmethod
    def from_values(cls, values: dict[str, str]) -> Settings:
        return cls(
            lab_mode=values.get("LAB_MODE", "").lower() == "true",
            pg_host=_require(values, "PG_HOST"),
            pg_port=_require_int(values, "PG_PORT"),
            pg_user=_require(values, "PG_USER"),
            pg_db=_require(values, "PG_DB"),
            restore_pg_port=_require_int(values, "RESTORE_PG_PORT"),
            restore_pg_db=_require(values, "RESTORE_PG_DB"),
            s3_endpoint_url=_require(values, "S3_ENDPOINT_URL"),
            s3_region=_require(values, "S3_REGION"),
            s3_bucket=_require(values, "S3_BUCKET"),
            retention_minutes=_require_int(values, "RETENTION_MINUTES"),
            backup_interval_seconds=_require_int(values, "BACKUP_INTERVAL_SECONDS"),
            pg_password=_require(values, "PG_PASSWORD"),
            writer_access_key=_require(values, "WRITER_ACCESS_KEY"),
            writer_secret_key=_require(values, "WRITER_SECRET_KEY"),
            attacker_access_key=_require(values, "ATTACKER_ACCESS_KEY"),
            attacker_secret_key=_require(values, "ATTACKER_SECRET_KEY"),
        )

    @classmethod
    def load(cls, path: Path = ENV_FILE) -> Settings:
        return cls.from_values(load_env(path))
