# PostgreSQL process-crash validation (2026-09-18)

## Result

Revision `5f503543add30f68e664c7aecd0bc57b4f9eff8f` passed a
disposable Debian 12 GCE campaign with PostgreSQL 15.19 on the actual shipped
Maki systemd, kernel NBD, pinned single-PV/LV, and XFS path. The cluster kept
its data directory and `pg_wal` on the encrypted volume. Data checksums,
`fsync`, `synchronous_commit`, and `full_page_writes` were all on.

The test committed 16 deterministic 64 KiB rows and then appended each result
to an independently fsynced acknowledgement ledger. While four pgbench clients
were active, systemd sent `SIGKILL` to the complete PostgreSQL service cgroup.
The postmaster PID changed from 18718 to 18782, pgbench exited 2 after observing
the dead backends, and the service restarted automatically. PostgreSQL detected
the interrupted cluster, replayed WAL, completed an end-of-recovery checkpoint,
and became ready. All 16 acknowledged rows and body hashes still matched.

The recovered cluster passed `pg_amcheck`, committed another 16 acknowledged
rows, and passed `pg_amcheck` again. PostgreSQL then stopped cleanly while the
packaged Maki lifecycle drained, detached, passed its offline check, attached,
and remounted the filesystem. PostgreSQL restarted with all 32 rows intact,
passed a third `pg_amcheck`, committed rows 32–47, and passed the final
`pg_amcheck`. The final 48 row IDs and body SHA-256 values exactly matched the
external ledger. A final Maki drain and offline check left no NBD connection or
device-mapper mapping.

This is evidence for one PostgreSQL process-crash and storage-lifecycle profile.
It is not production approval for PostgreSQL deployment, database migration,
backup/restore, replication, host power loss, or sustained load.

## Fixed environment

| Item | Executed value |
|---|---|
| Maki revision | `5f503543add30f68e664c7aecd0bc57b4f9eff8f` |
| Instance ID | `6657705714233978207` |
| Boot disk ID | `8915147096311541087` |
| Image | `debian-12-bookworm-v20260908` |
| Machine | `n2-standard-4` in `asia-northeast3-a` |
| NBD client | `3.27.1`, commit `f96f7fca3b37f4254c26c95f5c6c9dae70e030a1` |
| Storage graph | `/dev/nbd15`, one pinned PV/VG, 1.5 GiB LV, XFS |
| Maki volume | 2 GiB; local AES-256-GCM-SIV; 4 KiB device and crypto units |
| PostgreSQL | `15.19-0+deb12u1`; scale-3 pgbench schema; Unix socket only |
| Durability | checksums on; `fsync=on`; `synchronous_commit=on`; `full_page_writes=on` |
| Evidence | `/home/seorii/logs/maki-postgresql-crash-20260918` |

The Maki key was supplied as a systemd credential and was never collected from
the VM. PostgreSQL used a dedicated qualification unit ordered after
`maki-workload@pgqual.target`, with `Restart=on-failure` and cgroup-wide kill
semantics.

## Fault and oracle protocol

The campaign performed these steps:

1. Create the encrypted volume, attach the real kernel NBD/LVM/XFS stack, and
   initialize PostgreSQL with checksums.
2. Verify all four durability settings from the running server, initialize a
   scale-3 pgbench schema, and commit externally acknowledged rows 0–15.
3. Start four pgbench clients on two worker threads, wait three seconds, record
   the live postmaster PID, and send cgroup-wide `SIGKILL`.
4. Require the old PID to disappear, a distinct postmaster to become ready,
   pgbench to report connection loss, WAL recovery to run, and all 16 ACK rows
   to match before running `pg_amcheck`.
5. Commit rows 16–31, compare them with the ledger, and run `pg_amcheck` again.
6. Stop PostgreSQL, drain and stop Maki's packaged lifecycle, run the offline
   checker, restart the Maki lifecycle and PostgreSQL, compare all 32 rows, and
   run the third `pg_amcheck`.
7. Commit rows 32–47, compare all 48 rows and hashes, run the final
   `pg_amcheck`, then stop PostgreSQL and perform the final Maki drain, detach,
   and offline check.

The ACK-table writer commits a transaction before writing its ledger record,
then fsyncs both the ledger and its parent directory. Each body is derived from
the row ID and independently hashed during every readback. The crash was
injected into pgbench activity after the exact 16-row ACK prefix had completed;
pgbench transactions are integrity load and are not counted as external ACKs.

## Observations

| Observation | Result |
|---|---:|
| Harness checks | 12 passed, exit 0 |
| ACK rows before crash | 16 exact IDs and hashes |
| pgbench work before interruption | 590 transactions, 0 reported failed transactions before backend loss |
| pgbench crash result | exit 2; all four clients reported dead backends |
| Postmaster identity | PID 18718 → 18782 |
| WAL recovery | interrupted startup detected; redo completed; end-of-recovery checkpoint completed |
| Data page checksum version | 1 |
| `pg_amcheck` | 4 clean runs |
| ACK rows before/after Maki lifecycle restart | 32 / 32 exact |
| Final ACK rows | 48 exact IDs and hashes |
| Maki journal snapshot | appended sequence equals durable sequence; zero pending bytes and sync failures |
| Maki offline checks | passed after lifecycle stop and after final stop |

PostgreSQL logged `invalid record length ... wanted 24, got 0` at the end of WAL
during crash recovery, immediately followed by `redo done`, the recovery
checkpoint, and readiness. In this sequence that message identifies the normal
end of available WAL rather than a failed check; all four `pg_amcheck` runs and
the row/hash oracle were clean.

## Evidence and cloud cleanup

The private evidence contains input hashes, the external ledger, five database
snapshots, PostgreSQL settings and control data, pgbench output, the complete
PostgreSQL and Maki unit journals, four `pg_amcheck` outputs, drain and offline
checks, resource identities, and deletion observations. The evidence validator
recomputed every row prefix and checked process replacement, PostgreSQL
readiness, checksum state, empty `pg_amcheck` outputs, lifecycle results, and
cloud cleanup. It reported `evidence_validation=passed`. The 84-entry evidence
manifest verifies without a mismatch.

The first validator GREEN attempt required an initial pre-attach offline-check
file that was not part of the executed protocol. The campaign did perform the
two planned offline checks after a complete lifecycle stop and at final
cleanup. The validator expectation was corrected to those two checks; this was
a post-collection harness assertion error and no product step was retried.

The credential did not appear in any collected file, and GCP account and
network identities were redacted locally. The VM and auto-delete disk were
removed after evidence collection. Exact-name lookups failed and project-wide
queries recorded:

```text
remaining_maki_instances=0
remaining_maki_disks=0
```

## Scope and limits

This campaign covers one short PostgreSQL 15 workload, a scale-3 pgbench
schema, one controlled postmaster/cgroup crash, automatic WAL recovery, four
logical integrity scans, and one graceful encrypted-storage lifecycle restart.
The deterministic ACK table and PostgreSQL data/WAL files shared the encrypted
filesystem; the external ledger remained on the VM boot disk.

It does not crash the ACK writer between database commit and ledger fsync, kill
Maki or the VM concurrently with PostgreSQL, cut physical power, fill the
volume, measure latency or recovery objectives, run a soak, exercise remote
crypto, replication, tablespaces, point-in-time recovery, `pg_basebackup`, a
major-version upgrade, DB-native migration, distribution package upgrade,
multi-volume mapping, or a production PostgreSQL configuration. ClickHouse,
MinIO, and application-specific recovery contracts also remain unqualified.
