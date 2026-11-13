# Runbook

How to run the lab, run its pieces by hand, and fix the usual problems. All commands run from
the repository root. `make setup` creates `.venv`; the examples use `.venv/bin/lab`.

## Normal use

| Goal | Command |
|---|---|
| First-time setup | `make setup` |
| The whole story | `make demo` |
| Start the containers only | `make up` |
| Unit tests / lint | `make test` / `make lint` |
| Integration test (needs `make up`) | `make test-integration` |
| Wipe everything, including the vault | `make reset` |

`make reset` is the only way to remove COMPLIANCE-locked backups before they expire. That is the
point of the lock: nothing inside S3 can do it.

The integration test replaces the data in `shopdb` with a small data set and runs a real attack
and restore. Run `.venv/bin/lab seed` afterwards for the full data set.

## Running the scenario step by step

Use separate terminal windows where noted. Do not paste inline `# comments` after commands in
zsh; they are passed to the command as arguments.

1. `.venv/bin/lab up` starts the containers and creates the locked bucket.
2. `.venv/bin/lab lockcheck` must say `LOCKCHECK: PASS`.
3. `.venv/bin/lab seed` loads 5,000 customers, 200 products, 50,000 orders.
4. Window A: `.venv/bin/lab app-sim` (one new order about every second).
5. Window B: `.venv/bin/lab backup --loop` (every `BACKUP_INTERVAL_SECONDS`).
6. Window C: `.venv/bin/lab detect`.
7. `.venv/bin/lab attack` and type `ATTACK`. The vault table appears, then the INCIDENT line
   in window C.
8. `.venv/bin/lab restore`, then `.venv/bin/lab health --restore`.
9. `.venv/bin/lab report` writes `RESULTS.md` and `docs/img/timeline.png`.

Useful extras: `lab backups` lists every backup newest first with its tag and lock;
`lab health` checks production; `lab restore --before 2026-11-13T00:28:00Z` only considers
backups that started before that time; `lab perms` probes what the writer and attacker
identities can really do.

## Where things are

| Path | What |
|---|---|
| `.env` | Generated credentials and settings. Never commit. |
| `.lab/logs/` | One log per demo step. |
| `.lab/timeline.json` | The measured moments the report is built from. |
| `.lab/attacker.key` | The simulated attacker's key. |
| `.lab/last_clean_manifest.json` | Baseline row counts for the health check. |
| `.lab/tmp/` | Scratch dumps, deleted after each use. |

## Troubleshooting

**`Not set up: missing .env`.** Run `make setup`.

**`Cannot use Postgres on 127.0.0.1:5432`.** The stack is not running. Run `make up`. If port
5432 or 5433 is taken by another Postgres on your machine, stop that one.

**`lab lockcheck` fails.** Read the reasons it prints. Do not continue: without a working lock
the demo proves nothing. Make sure the vault image is current (`docker compose pull vault`). The
design allows swapping the vault for RustFS (`rustfs/rustfs`) because the Python code only uses
generic S3 calls; that swap has not been tried here, so run `lockcheck` after changing it.

**`no locked clean backup in the vault yet: run lab backup first`.** The attack needs at least
one clean backup whose lock is still running (10 minutes by default). Run `lab backup`, then
attack.

**`timeline is missing ... Run: ...`.** The report needs a full run in order: `detect` running
before `attack`, then `restore`. Run the steps in the order above, or use `make demo`.

**`Backup failed (...)`.** Read the first line. Common causes: Docker stopped, or the vault is
still starting. The loop keeps going and reports each failed cycle in red.

**`lab health` talks to the wrong database, or options act strangely.** This project pins
`click==8.1.8` for `typer==0.12.5`. Re-run `.venv/bin/python -m pip install -e .`.

**A demo was interrupted.** Ctrl+C is meant to stop the background processes. To check nothing is
left over: `pgrep -fl "lab.cli"` should print nothing.

**Start over.** `make reset && make setup && make demo`.

## Reading the vault table after an attack

- *BLOCKED*: the vault refused and the data is still there.
- *BLOCKED (not the lock)* on "Delete the bucket": it failed because the bucket is not empty,
  which would also stop an unlocked bucket from being deleted. Do not read it as lock proof.
- *ALLOWED, DATA INTACT*: the call succeeded but did no damage. A delete with no version id
  only adds a delete marker; an overwrite only adds a new version.
- *DESTROYED*: something was lost. That would be a real failure of the vault; stop and
  investigate.
