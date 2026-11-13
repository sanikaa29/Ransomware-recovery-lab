"""Generate local-only credentials: ``.env`` and the vault identity file ``.lab/s3.json``.

Stdlib only, so it can run before anything else is installed. Secrets are never printed.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import string
from pathlib import Path

from lab.config import ENV_FILE, LAB_DIR, ROOT, parse_env

PLACEHOLDER = "change-me"
SECRET_KEYS = (
    "PG_PASSWORD",
    "WRITER_ACCESS_KEY",
    "WRITER_SECRET_KEY",
    "ATTACKER_ACCESS_KEY",
    "ATTACKER_SECRET_KEY",
)
_UPPER_DIGITS = string.ascii_uppercase + string.digits
_ALNUM = string.ascii_letters + string.digits


def _random(alphabet: str, length: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_secrets() -> dict[str, str]:
    """Fresh random credentials, alphanumeric so they are safe in URLs and shells."""
    return {
        "PG_PASSWORD": _random(_ALNUM, 24),
        "WRITER_ACCESS_KEY": _random(_UPPER_DIGITS, 20),
        "WRITER_SECRET_KEY": _random(_ALNUM, 40),
        "ATTACKER_ACCESS_KEY": _random(_UPPER_DIGITS, 20),
        "ATTACKER_SECRET_KEY": _random(_ALNUM, 40),
    }


def render_env(template: str, overrides: dict[str, str]) -> str:
    """Return the template with ``KEY=...`` lines replaced by ``overrides``."""
    lines = []
    for line in template.splitlines():
        key, sep, _ = line.partition("=")
        name = key.strip()
        if sep and not line.lstrip().startswith("#") and name in overrides:
            line = f"{name}={overrides[name]}"
        lines.append(line)
    return "\n".join(lines) + "\n"


# Backup writer permissions, each scoped to the backup bucket (see build_s3_config).
WRITER_ACTIONS = ("Admin", "Read", "Write", "List", "Tagging")

# Candidate writer action sets for `lab experiments`. Phase 2 showed the bucket-scoped set (A)
# cannot upload with Object Lock headers; these find the narrowest set that can.
CANDIDATES: dict[str, list[str]] = {
    "exp-a-scoped": ["Read:{b}", "Write:{b}", "List:{b}", "Tagging:{b}"],
    "exp-b-global": ["Read", "Write", "List", "Tagging"],
    "exp-c-scoped-admin": ["Admin:{b}", "Read:{b}", "Write:{b}", "List:{b}", "Tagging:{b}"],
    "exp-d-scoped-no-tag": ["Read:{b}", "Write:{b}", "List:{b}"],
}
EXPERIMENT_KEYS_FILE = "experiments.json"


def generate_candidate_keys() -> dict[str, dict[str, str]]:
    return {
        name: {"access": _random(_UPPER_DIGITS, 20), "secret": _random(_ALNUM, 40)}
        for name in CANDIDATES
    }


def build_s3_config(
    values: dict[str, str], candidates: dict[str, dict[str, str]] | None = None
) -> dict[str, list[dict[str, object]]]:
    """SeaweedFS ``-s3.config`` identities.

    backup-writer: read/write/list/tagging plus ``Admin:<bucket>``, all limited to the backup
        bucket. Admin on that one bucket is required: SeaweedFS 4.53 refuses to set Object
        Lock retention (on upload or afterwards) for any narrower set. See docs/DECISIONS.md.
    attacker: simulated stolen global admin credentials.
    candidates: extra throwaway identities, only present while running `lab experiments`.
    """
    bucket = values["S3_BUCKET"]
    extra = [
        {
            "name": name,
            "credentials": [{"accessKey": keys["access"], "secretKey": keys["secret"]}],
            "actions": [a.format(b=bucket) for a in CANDIDATES[name]],
        }
        for name, keys in (candidates or {}).items()
    ]
    return {
        "identities": [
            {
                "name": "backup-writer",
                "credentials": [
                    {
                        "accessKey": values["WRITER_ACCESS_KEY"],
                        "secretKey": values["WRITER_SECRET_KEY"],
                    }
                ],
                "actions": [f"{a}:{bucket}" for a in WRITER_ACTIONS],
            },
            {
                "name": "attacker",
                "credentials": [
                    {
                        "accessKey": values["ATTACKER_ACCESS_KEY"],
                        "secretKey": values["ATTACKER_SECRET_KEY"],
                    }
                ],
                "actions": ["Admin", "Read", "Write", "List", "Tagging"],
            },
            *extra,
        ]
    }


def _write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.chmod(path, mode)


def _check_no_placeholders(values: dict[str, str]) -> None:
    bad = [k for k in SECRET_KEYS if values.get(k, PLACEHOLDER) == PLACEHOLDER]
    if bad:
        raise SystemExit(f"{', '.join(bad)} still unset in .env; re-run with --force")


def generate(
    env_file: Path,
    lab_dir: Path,
    template_file: Path,
    force: bool = False,
    experiments: bool = False,
) -> list[str]:
    """Create ``.env`` (if absent or forced) and always (re)render ``s3.json`` from it.

    With ``experiments=True`` also adds throwaway candidate identities (keys saved to
    ``.lab/experiments.json``). A normal run removes them again.
    """
    notes: list[str] = []
    if env_file.exists() and not force:
        values = parse_env(env_file.read_text(encoding="utf-8"))
        _check_no_placeholders(values)
        notes.append(f"kept existing {env_file.name} (use --force to regenerate)")
    else:
        text = render_env(template_file.read_text(encoding="utf-8"), generate_secrets())
        _write(env_file, text, 0o600)
        values = parse_env(text)
        notes.append(f"wrote {env_file.name} with random credentials (not displayed)")
        if force:
            notes.append(
                "WARNING: existing Postgres volumes keep the OLD password; run `make reset`"
            )
    candidates = generate_candidate_keys() if experiments else None
    keys_file = lab_dir / EXPERIMENT_KEYS_FILE
    if candidates:
        _write(keys_file, json.dumps(candidates, indent=2) + "\n", 0o600)
        notes.append(
            f"added {len(candidates)} experiment identities (keys in .lab/{keys_file.name})"
        )
    else:
        keys_file.unlink(missing_ok=True)
    # 0644: the file is mounted into a container that may run as another uid. Local lab only.
    config = json.dumps(build_s3_config(values, candidates), indent=2) + "\n"
    _write(lab_dir / "s3.json", config, 0o644)
    (lab_dir / "logs").mkdir(parents=True, exist_ok=True)
    notes.append("wrote .lab/s3.json (vault identities)")
    return notes


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate local lab credentials.")
    parser.add_argument("--force", action="store_true", help="regenerate .env with new secrets")
    parser.add_argument(
        "--experiments", action="store_true", help="add throwaway writer identities for testing"
    )
    args = parser.parse_args()
    notes = generate(
        ENV_FILE, LAB_DIR, ROOT / ".env.example", force=args.force, experiments=args.experiments
    )
    for note in notes:
        print(note)


if __name__ == "__main__":
    main()
