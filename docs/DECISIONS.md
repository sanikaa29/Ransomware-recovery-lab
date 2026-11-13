# Design decisions

Short records of choices that came from testing the real system, not from assumptions.

## 001: The backup writer has admin rights on the backup bucket

**Status:** accepted (chosen by the project owner after testing).

**Context.** The original design gave the `backup-writer` identity only read, write, list and
tagging on the backup bucket, with no bucket administration. Each backup must be uploaded with a
per-object COMPLIANCE retention date. On SeaweedFS 4.53 (`weed version`: `30GB 4.53 4ab66fb76`),
uploads carrying retention headers, and `PutObjectRetention` after a plain upload, were refused
for every narrower permission set we tried.

Result of `lab experiments` (run `python -m lab.setup_env --experiments` first to create the
candidate identities) against the real vault (each set scoped to `lab-backups` unless noted):

| Writer permissions | Upload with COMPLIANCE headers | Upload, then set retention |
|---|---|---|
| Read, Write, List, Tagging | AccessDenied | AccessDenied |
| Read, Write, List, Tagging (all buckets) | AccessDenied | AccessDenied |
| Read, Write, List (no Tagging) | AccessDenied | AccessDenied |
| **Admin, Read, Write, List, Tagging** | **allowed** | **allowed** |

Reading an object's retention was also refused for the narrower sets.

**Decision.** `backup-writer` gets `Admin:lab-backups` plus Read, Write, List and Tagging, all
limited to that one bucket. `lab perms` checks the limit: the writer should be unable to touch
other buckets or shorten retention.

**Verified (12 Nov 2026, SeaweedFS 4.53, `lab lockcheck` + `lab perms`: 0 mismatches).** With this
writer: locked upload, tag read, version listing and retention read were allowed. Deleting a
locked version, shortening its retention, suspending versioning (`InvalidBucketState`), creating a
bucket, deleting another bucket and writing to another bucket were all blocked. Deleting an
unlocked version was allowed. The locked test version was still readable after every attack.

**What stays protected.** The lock is enforced by the vault's object state, not by who asks.
In `lab lockcheck` and `lab perms`, even the global-admin `attacker` identity could not delete a
locked version, shorten its retention, or suspend versioning. A bucket-scoped admin is a subset
of that identity, so the same blocks apply to it.

**What this costs.**
- A stolen writer key is admin on the backup bucket, not just a write-only key. It can still
  not remove or shorten existing locked backups, but it can change anything that is not locked.
- It can upload objects with a very long retention date, which would tie up storage until that
  date. In a real deployment this needs quota alerts.
- The writer can delete *unlocked* versions (Write includes delete). Every backup must therefore
  be uploaded locked; the backup code must treat a failed lock as a failed backup.

**Alternatives considered.**
- Least-privilege writer plus a bucket default retention rule. Better separation, but S3
  default retention is whole days (minimum one day), which removes the minutes-level
  `RETENTION_MINUTES` setting, and applying defaults to plain uploads was not tested here.
- Switching the vault to RustFS. Unknown whether it offers finer permissions; not tried.

**Production note.** A real deployment would use a vault with a distinct "write and lock only"
permission, or a separate account that holds the vault, so a compromised backup service cannot
administer the bucket.
