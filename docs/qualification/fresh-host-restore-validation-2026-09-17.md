# Fresh-host backing restore validation (2026-09-17)

## Result

Revision `ece7e39171cbe9dd88b9abbc02119f6bb9b7fb9e` passed a
fresh-host restore of one unchanged v2 encrypted backing on two sequential
disposable Debian 12 GCE VMs. The source VM committed 32 SQLite WAL rows before
appending each row to an independently fsynced acknowledgement ledger. It then
drained the daemon, stopped the packaged systemd lifecycle, passed the offline
check, and exported the backing, configuration, attach identity and credential.

The source VM and its auto-delete boot disk were deleted before the target VM
was created. The target VM installed the same built runtime, created fresh
system users and runtime directories, restored the files with ownership mapped
to the new `maki` UID, and passed `maki check` before attachment. The installed
systemd graph mounted the restored kernel NBD/LVM/XFS stack and an independent
reader matched all 32 SQLite rows and payload hashes with
`PRAGMA integrity_check=ok`.

The target then committed 16 new rows with the same DB-before-ledger ordering.
After a complete drain, target stop and fresh lifecycle start, it matched all 48
rows and hashes again with `integrity_check=ok`. The final drain and offline
check left no NBD connection or device-mapper mapping. Both target resources
were deleted, and project-wide name-scoped queries returned zero `maki-*`
instances and disks.

## Fixed environment

| Item | Value |
|---|---|
| Source revision | `ece7e39171cbe9dd88b9abbc02119f6bb9b7fb9e` |
| Source instance ID | `4826010387076231354` |
| Source boot disk ID | `1399048181937221818` |
| Target instance ID | `2289338711340887598` |
| Target boot disk ID | `7139011302886092334` |
| Image | `debian-12-bookworm-v20260908` |
| Machine | `n2-standard-4` |
| NBD client | `3.27.1`, commit `f96f7fca3b37f4254c26c95f5c6c9dae70e030a1` |
| Storage graph | `/dev/nbd15`, one pinned PV/VG/LV, XFS |
| Maki volume | 512 MiB, local AES-256-GCM-SIV credential |
| Database | SQLite WAL, `synchronous=FULL`, `wal_autocheckpoint=1` |
| Evidence | `/home/seorii/logs/maki-fresh-host-restore-20260917` |

The source and target instance IDs and boot disk IDs are all distinct. The
evidence validator recalculates both ledgers, every deterministic row hash, all
three DB snapshots, instance and disk deletion results, and the final empty
resource lists. Its result is `evidence_validation=passed`; the 154-entry
evidence manifest verifies with zero failures. GCP account identities are
redacted. The generated archive containing the disposable credential was
removed after target verification and cloud cleanup; its SHA-256 remains in the
source export manifest.

The same revision's nine tracked release gates passed locally. GitHub Actions
run `35191166615` passed the baseline suite on Linux and Windows.

## Harness corrections

Three harness failures were retained in the evidence and classified separately
from product behavior:

1. The source writer ran under `sudo`, so `Path.home()` placed the external
   ledger in `/root`. The resume step copied that completed ledger only after
   rechecking all 32 DB rows and hashes against it.
2. The ad hoc runtime tar contained the plugin file but no explicit parent
   directory entry. Extraction under `umask 077` created `/usr/lib/maki` as
   `0700`, and nbdkit failed before loading the plugin. Setting the packaging
   directory to its required `0755` mode made the plugin readable by `maki`.
3. The first target resume treated `systemctl reset-failed` for unloaded static
   units as fatal. Making that cleanup idempotent allowed the unchanged product
   path to run.

These failures reinforce two restore requirements: recreate package directory
modes explicitly, and remap restored backing ownership to the fresh host's
service UID. This campaign used an ad hoc artifact tar, so it does not qualify a
distribution package installation or upgrade.

## Scope and limits

This result covers a graceful backup and restore of one unchanged v2 backing,
its exact configuration and key, with a local provider and SQLite on one
single-PV/LV topology. It proves that the source process, kernel state and boot
disk are not required once those artifacts have been captured and verified.

It does not cover a legacy-v1 migration, DB-native logical backup, credential
or endpoint rotation, remote-provider failure, multi-LV/internal mappings,
foreign-device replacement, a crash during capture or restore, distribution
package upgrade, a different database, performance targets, soak load or
physical power loss. Protect credentials separately from general backups and
logs; this test's combined archive was disposable qualification material, not a
recommended production secret-distribution format.
