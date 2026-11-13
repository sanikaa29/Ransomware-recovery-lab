# Threat model

What this lab protects, from whom, and where the protection stops. It describes the lab as it is
tested, not an ideal product.

## What is being protected

The backups of the shop database, kept in the vault bucket `lab-backups`, so that the shop can
be restored after its live database is damaged.

## Who the attacker is

A simulated attacker who has:

- write access to the production database (enough to encrypt rows and create a table), and
- **stolen vault admin credentials** (the `attacker` identity: global admin on the vault).

The attacker does not have a shell on the vault's host, the Docker daemon, or the laptop.

## What happens, action by action

All results below were observed in real runs (`lab lockcheck`, `lab perms`, `lab attack`).

| Attacker action | Outcome | Why |
|---|---|---|
| Encrypt customer contact details and order notes in the live database | **Succeeds** | The attacker has database write access. The simulation exists to show recovery, not prevention. |
| Create the ransom note table | **Succeeds** | Same. It also makes the next backup recognisably suspect. |
| Delete a locked backup version | **Blocked** (`AccessDenied`) | COMPLIANCE retention: the object version cannot be deleted until its retain-until date. |
| Shorten a locked version's retention | **Blocked** (`AccessDenied`) | COMPLIANCE retention can only be extended. |
| Suspend bucket versioning | **Blocked** (`InvalidBucketState`) | Versioning cannot be suspended on an Object Lock bucket. |
| Delete the bucket | **Blocked**, but only because it is not empty (`BucketNotEmpty`) | This says nothing about the lock. An empty bucket could be deleted. |
| Delete a backup with no version id | **Allowed, harmless** | Adds a delete marker. The locked version underneath is untouched, and restore reads exact versions. |
| Overwrite a backup key | **Allowed, harmless** | Adds a new, unlocked version. The locked original is untouched. Restore checks the SHA-256 of the exact version the manifest names, so a swapped object would be rejected. |
| Let the next backup run | **Poisoned backup is stored** | The backup job faithfully copies damaged data. Restore skips it because its manifest and tag say suspect. |

The key property: the lock is enforced by the *state of the object*, not by who is asking. Even
the global admin identity cannot override it.

## What is not protected

| Gap | Detail |
|---|---|
| **Control of the vault host** | Someone who can run `docker volume rm` or delete the volume's files destroys every backup. No S3 setting stops that. This lab keeps database, vault and credentials on one laptop, so it is not an air gap. Production would keep the vault in a separate account or location. |
| **Time** | Retention is 10 minutes so the lab stays tidy. When it expires, deletion is allowed. Real retention is days or years. |
| **The writer is a bucket admin** | See ADR 001 in [DECISIONS.md](DECISIONS.md). A stolen writer key can administer the backup bucket (not remove or shorten locked backups), and can delete *unlocked* versions. Every backup is therefore uploaded locked, and after each upload the code reads the retention back and fails the backup if it is not locked. A stolen writer key could also set a very long retention and tie up storage. |
| **Tags are mutable** | Anyone with write access can change an object's `health` tag. Restore therefore skips a backup if either its tag or its manifest says suspect, and a "clean" tag never overrides a suspect manifest. A tampered tag cannot make a bad backup look good; it could only make a good one look bad. |
| **Narrow health rules** | The checks catch this attack: fewer than 99% valid emails, the ransom table's existence, or a drop of more than 5% in any table's rows against the last clean backup. Subtle corruption, or an attack that preserves email format, would pass them. |
| **A backup of damage made before detection** | Anything the attack changed before the next backup is in that backup. Restore skips only backups the health rules flag. |
| **Credentials on disk** | `.env` holds the lab's keys, including the stand-in for stolen admin credentials. That is by design for a demo. |
| **Clock** | `lab lockcheck` reports skew between the vault clock and the host (-0.4 s in a real run). Retention dates come from the host's clock at upload time; a badly wrong clock would shorten or lengthen protection. |
| **Cutover** | Restore proves recovery into a clean-room database. Pointing the shop at it is not modelled. |
| **The attacker is not adaptive** | It runs a fixed script. A real attacker who knew about the health rules could try to stay under them. |

## Assumptions

- Docker's networking binds only to `127.0.0.1`, so nothing outside the machine can reach the
  database or vault.
- The SeaweedFS version tested (4.53) enforces COMPLIANCE retention as `lockcheck` shows. Other
  versions or backends must be re-tested.
- Backups are only trusted after verification: SHA-256 of the dump, then restored-database
  health, then row counts and per-table checksums equal to the manifest.

## What a production design would add

A separate account or site for the vault, a write-and-lock-only identity for the backup service,
alerts on unusual retention dates and storage growth, longer retention, a restore environment
isolated from production, health rules tuned to the application, and regular restore tests.
