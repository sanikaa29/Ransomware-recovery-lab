"""S3 access to the backup vault (boto3, path-style). Endpoint, keys and region come only
from Settings, so the code stays backend-agnostic (SeaweedFS today, RustFS as fallback)."""

from __future__ import annotations

import time
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Literal

import boto3
from botocore import UNSIGNED
from botocore.client import BaseClient
from botocore.config import Config
from botocore.exceptions import BotoCoreError, ClientError

from lab.config import Settings
from lab.vault_rules import Outcome, classify, extract_error, skew_seconds, verified_outcome

Role = Literal["writer", "attacker", "anonymous", "bogus"]
_ALREADY_EXISTS = frozenset({"BucketAlreadyOwnedByYou", "BucketAlreadyExists"})
# Deliberately fake, not a secret: used to prove the vault rejects unknown credentials.
_BOGUS_KEY, _BOGUS_SECRET = "AKIAINVALIDINVALID00", "invalid" * 5


def client_with_keys(
    settings: Settings, key: str | None, secret: str | None, *, signed: bool = True
) -> BaseClient:
    """S3 client for the vault using explicit keys (``signed=False`` sends no signature)."""
    return boto3.client(
        "s3",
        endpoint_url=settings.s3_endpoint_url,
        region_name=settings.s3_region,
        aws_access_key_id=key,
        aws_secret_access_key=secret,
        config=Config(
            signature_version="s3v4" if signed else UNSIGNED,
            s3={"addressing_style": "path"},
            retries={"max_attempts": 3, "mode": "standard"},
        ),
    )


def make_client(settings: Settings, role: Role) -> BaseClient:
    """``writer`` = backup identity; ``attacker`` = the admin credentials the attacker steals.

    ``anonymous`` (unsigned requests) and ``bogus`` (unknown keys) exist only so tests can prove
    the vault enforces authentication at all.
    """
    if role == "writer":
        return client_with_keys(settings, settings.writer_access_key, settings.writer_secret_key)
    if role == "attacker":
        return client_with_keys(
            settings, settings.attacker_access_key, settings.attacker_secret_key
        )
    if role == "bogus":
        return client_with_keys(settings, _BOGUS_KEY, _BOGUS_SECRET)
    return client_with_keys(settings, None, None, signed=False)


def try_call(call: Callable[[], object]) -> tuple[Outcome, str]:
    """Run one S3 call; report whether it was blocked/allowed and the error code."""
    try:
        call()
    except ClientError as exc:
        code, status = extract_error(exc)
        return classify(code, status), code
    except BotoCoreError as exc:
        return "error", type(exc).__name__
    return "allowed", "-"


def try_call_verified(
    call: Callable[[], object], still_intact: Callable[[], bool]
) -> tuple[Outcome, str]:
    """Like ``try_call`` but decided by state: blocked only if the call failed AND the
    target survived (checked afterwards with ``still_intact``)."""
    outcome, code = try_call(call)
    try:
        intact = still_intact()
    except (BotoCoreError, ClientError):
        intact = False
    return verified_outcome(outcome, intact), code


def wait_for_s3(client: BaseClient, timeout_seconds: int = 60) -> None:
    """The compose healthcheck covers the master only; wait until the S3 gateway answers."""
    deadline = time.monotonic() + timeout_seconds
    while True:
        try:
            client.list_buckets()
            return
        except (BotoCoreError, ClientError):
            if time.monotonic() >= deadline:
                raise
            time.sleep(2)


def ensure_locked_bucket(client: BaseClient, bucket: str) -> None:
    """Create ``bucket`` with Object Lock enabled at creation (it cannot be added later)."""
    try:
        client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    except ClientError as exc:
        if extract_error(exc)[0] not in _ALREADY_EXISTS:
            raise


def object_lock_enabled(client: BaseClient, bucket: str) -> bool:
    try:
        config = client.get_object_lock_configuration(Bucket=bucket)
    except ClientError:
        return False
    return config.get("ObjectLockConfiguration", {}).get("ObjectLockEnabled") == "Enabled"


def provision(settings: Settings) -> None:
    """Create the backup bucket with Object Lock. Uses the admin identity, the same
    credentials the attack later 'steals': provisioning is the one job that needs admin."""
    admin = make_client(settings, "attacker")
    wait_for_s3(admin)
    ensure_locked_bucket(admin, settings.s3_bucket)
    if not object_lock_enabled(admin, settings.s3_bucket):
        raise RuntimeError(
            f"bucket {settings.s3_bucket!r} exists but Object Lock is not enabled; "
            "it must be set at creation. Run `make reset` and retry."
        )


def clock_skew(client: BaseClient, bucket: str) -> float | None:
    """Vault clock minus local clock in seconds, or None if the vault sends no Date header."""
    try:
        headers = client.head_bucket(Bucket=bucket)["ResponseMetadata"]["HTTPHeaders"]
    except (BotoCoreError, ClientError):
        return None
    date = headers.get("date")
    return skew_seconds(date, datetime.now(UTC)) if date else None
