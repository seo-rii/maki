# Deployment qualification profile

Use this record to turn the remaining work in [current status](../status.md)
into acceptance criteria for one deployment. A filled-out record is a plan;
approval requires the linked evidence. Reference-provider campaigns and a
passing CI run do not automatically approve another provider or environment.

## Record the intended deployment

| Field | Required value |
|---|---|
| Software | Commit, candidate package SHA-256, Rust/build profile, dependencies |
| Host | Distribution, kernel, systemd, CPU/RAM, nbdkit and nbd-client versions |
| Storage | Backing filesystem/device/storage class, mount options, NBD/PV/VG/LV/fs UUID pins, v2 or v3, virtual size, shard/unit sizes |
| Crypto | Provider and contract version, key/profile reference, transport/mapping, endpoints, batch/retry/concurrency limits |
| Security | Credential version references (no secret values), TLS trust policy, memory-lock/swap/core-dump policy, installed unit/drop-ins |
| Workload | DB/application version and settings, data size/fill ratios, request sizes, concurrency, cache state and WAL/temp growth |
| Acceptance | Minimum throughput; maximum p95/p99, stall, recovery, backup/restore time; memory ceiling and headroom; required free-space margin |
| Recovery | Backup location/retention, off-host ACK oracle, credential recovery owner, restore/cutover/rollback owner and maintenance window |
| Outcome | Each case's run/revision, log/artifact location, exit status, pass/fail/skipped, and exact approved scope |

Choose the numerical thresholds with the workload owner before measurement.
No default in a sample TOML establishes an SLO. Store sanitized configuration
and package hashes with results; retain credentials through the existing
secret-management process, separately from general backups and reports.

## Required operational cases

1. **Installed lifecycle and target identity.** Use the selected package and
   the supported pinned single-PV/single-data-LV XFS topology. Verify startup,
   readiness, workload gating, stop/drain, restart and cleanup, including the
   effective mount and sandbox settings. A successful `maki status` query is
   not the privileged workload gate. Follow [operations](../operations.md)
   and [storage recovery](../storage-recovery.md).
2. **Vendor contract and maintenance.** Validate every selected endpoint with
   the actual mapping/key/profile. Exercise individual and total outage,
   recovery after the application's maximum permitted outage, and endpoint
   address replacement. Record whether `stall` or `bounded-error` meets the
   application contract. Repeat bearer/mTLS, server-CA and address rotation
   with shared clients, transition failures and a rollback window using
   [key rotation](../key-rotation.md). Existing 12–20-second provider-reset
   evidence is not a minutes-long outage test.
3. **Performance, memory and space.** Fill in the criteria and collect
   [performance and memory profiles](../performance.md). Include provider
   delays, checkpoint/recovery peaks and the backing-full recovery procedure.
   Distinguish an I/O stall from a failed write and collect DB recovery evidence
   when the application receives an error.
4. **Backup, fresh-host restore and migration.** Use an application-consistent
   backup or the documented stopped-backing procedure. Restore onto the
   selected destination package/image, verify identity/key/profile, application
   integrity and acknowledged data, then demonstrate continued writes and a
   restart. Test the migration cutover and rollback decision before retiring
   the source. Follow [durable recovery](../durable-recovery.md). For protected
   backings, apply the separate [witness procedure](../rollback-protection.md#backup-and-recovery-procedure).

Debian 12 package install/upgrade, stopped SQLite migration and fresh-host
restore have scoped evidence already. PostgreSQL 15 and 17 and all three remote
transports also have scoped results. Reuse that evidence only for what it
actually covers; [the qualification index](../qualification/README.md) links
the original environment, revision and limitations. Other DBs, distributions,
RAID and multi-LV recovery are separate support decisions, not implicit
requirements for the existing topology.

Long-duration fuzzing, soaks and stronger power-loss tiers remain on the
[external checklist](../testing.md#external-qualification-checklist). They are
separate campaign work; this profile neither runs them nor marks them passed.

## Approve and retain

Keep one result record per profile and compare every measurement with its
predeclared threshold. An unavailable tool, missing credential or skipped case
leaves that case unqualified. Record failures and recovery actions, not just
the final successful attempt. Approve only the profile whose acceptance cases
passed and retain its package, source provenance, sanitized configuration and
recovery instructions together. Until that approval exists, preserve the
evaluation-only status in the public support matrix.
