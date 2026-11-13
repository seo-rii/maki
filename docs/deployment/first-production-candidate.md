# First production candidate campaign

This is an execution plan for one candidate, with **all campaign results
pending**. Fill out the [qualification profile](qualification-profile.md) and
retain the case results below before changing the approval in
[current status](../status.md). The proposed baseline uses Debian 12,
`local-aes-gcm-siv`, a directory backing, and one whole NBD device with one PV,
one VG and one linear XFS data LV. Experimental rollback protection and remote
providers require their own additional cases if selected.

## Resolve the deployment inputs

These decisions must be recorded before the candidate is measured. Example
configuration values and past campaign measurements do not fill them in.

| Decision | Initial value |
|---|---|
| OS and service stack | Debian 12; record the exact image, kernel and systemd packages, architecture, CPU and RAM |
| Storage | **Unresolved:** backing filesystem/device or cloud storage class, mount options, physical capacity and expected fill ratios |
| Volume | **Unresolved:** v2 or v3, exported size, crypto/shard geometry, journal limits, reserves and cache/admission settings; keep full NBD/LVM/XFS identity pins |
| Workload | **Unresolved:** DB/application and version, durability settings, data/WAL/temp sizes, growth, concurrency and request mix; [PostgreSQL](postgres.md) is an existing example, not an automatically selected workload |
| Latency and throughput | **Unresolved:** minimum sustained throughput and maximum application p95/p99 for normal load, checkpoint pressure and recovery to steady state |
| Recovery and resources | **Unresolved:** maximum outage/recovery/restore time, service timeout policy, daemon RSS and cgroup ceilings, required memory and backing-space headroom |
| Fault campaign | **Unresolved:** disposable hosts/devices, reset/power-loss tier, repetition counts, interruption points and resource limits |
| Operations | **Unresolved:** backup retention/location, credential recovery reference, upgrade source package and recovery operator |

Choose the numerical limits before running the cases. A missing limit leaves
the corresponding acceptance decision pending. Keep credentials in the chosen
secret store; the profile and general evidence contain references, not values.

## Freeze the candidate and evidence

Build the final integrated commit with [release preparation](../releasing.md).
Retain the Maki package, source archive, manifest and checksums, plus the exact
versioned `nbd-client >= 3.27.0` package, its source/patches/build recipe and
checksum. Verify both package hashes on each destination before installation.
Install these artifacts for the campaign; a separate source build does not
establish that the candidate package works.

Record installed package versions, kernel, systemd, nbdkit, backing storage
identity and geometry, effective units/drop-ins, and sanitized configuration
hashes. Keep the observed NBD backend, PV/VG/LV and XFS UUID pins with the run.
Use separate failure domains for the workload host, acknowledgement ledger and
restore destination. A directory elsewhere on the volume, or a container on
the same reset host, is not an independent ledger.

The workload driver gives every transaction a stable ID and expected payload
hash. After the DB reports a successful durable commit, the driver appends that
ID/hash to the external ledger and `fsync`s it before counting it as an
acknowledged transaction. After recovery, require every durably ledgered
transaction to exist with the expected contents and run the DB's integrity
checks. A transaction committed immediately before a lost response or ledger
append may also exist: extra, unledgered commits are not evidence of corruption.
Keep uncertain outcomes separate from confirmed failures and confirmed ACKs.

Validate the oracle first: removing a required transaction or changing its
payload in a disposable copy must make verification fail. Keep that negative
control result beside the successful control run. A fault case with no observed
fault, no completed ledger writes or an unavailable verifier is inconclusive.

## Run the installed stack

Run the cases on the declared disposable hosts/devices. Register the workload
with the packaged lifecycle and use [operating procedures](../operations.md)
and [storage recovery](../storage-recovery.md). Preserve each failed attempt and
its state before recovery; a later successful retry does not replace it.

| Case | Execution | Required result and evidence |
|---|---|---|
| FPC-01: install and identity | Install the exact Maki/nbd-client packages on a fresh host; provision the pinned topology, start the lifecycle and execute the oracle control workload. | Package/config hashes match; effective sandbox and mount options are recorded; readiness and the per-start identity gate precede workload start; ACK contents and DB integrity match. |
| FPC-02: dirty stop and busy unmount | Create dirty filesystem/DB state, stop the lifecycle with I/O admission open, then restart. Separately obstruct unmount with a controlled holder and request a planned stop. | Trace workload stop, unmount, daemon drain and restart. A failed cleanup is reported without claiming an inactive clean volume or automatically restarting a deliberately stopped workload. Record the live mount/device/daemon state and verify ACKs after the documented recovery. |
| FPC-03: interrupted attach | Interrupt the helper after NBD connection, LVM activation and mount; repeat with timeout and SIGKILL. Include duplicate-start, foreign-backend and cleanup-failure controls. | Workloads are quiesced before recovery cleanup; every mutation is identity-bound; successful cleanup permits reattach, while foreign identity or failed cleanup prevents restart. Record attempts and verify start-rate limits, preserved records and ACKs. |
| FPC-04: long and repeatedly interrupted recovery | Recover the declared maximum journal/fill profile. Separately stop progress, interrupt scan/repair/replay at multiple points, and inject repeated startup timeout or cgroup OOM before a final attempt with the declared normal budget. | A progressing recovery can finish within the agreed recovery bound; stalled work does not gain endless startup extensions. Retain every attempt's progress, timeout/OOM events, cumulative I/O, RSS/cgroup peak and duration. Final ACK and integrity checks pass. Progress notifications alone do not establish persisted replay progress across restarts. |
| FPC-05: full backing and DB recovery | Grow unrelated disposable data on the backing filesystem through the admission threshold while DB writes continue. Remove only that filler to restore the declared reserve, then follow the lifecycle recovery procedure. | Record free bytes, admission errors, DB/XFS behavior and ACK boundary. Rejected or uncertain writes are distinguished from durable ACKs. After restoring backing headroom, DB integrity, old ACKs, new commits and another restart all succeed. Deleting data inside Maki is not the space-recovery mechanism. |
| FPC-06: fresh-host restore | Create the documented DB-consistent or stopped-backing backup at a recorded ledger cutoff. Restore the exact candidate on a different host and supply the credential through its separate recovery path. | All ACKs included by the backup's declared cutoff match; identity/key checks and DB integrity pass; continued writes and a further restart succeed. Measure backup/restore time and retention behavior. Post-cutoff writes are outside that backup's recovery claim. |
| FPC-07: stopped upgrade | Retain the declared source and target package hashes. Stop with the source package, install the candidate, reattach and perform DB verification and more writes. Exercise the chosen rollback procedure on a separate disposable copy. | Config/credential references and volume identities survive; no maintainer script starts a live volume; old and new ACKs survive restart. Record the actually supported downgrade/restore boundary; do not assume an in-place format conversion or arbitrary package downgrade works. |
| FPC-08: 72-hour workload soak | Run the selected DB/application mixed load for at least 72 hours at the declared working set and fill ratios, including fresh allocation, overwrites, checkpoints and planned restarts. For v3, include TRIM under load. | Continuous external ACK evidence, DB integrity and final offline deep check pass. Report per-class p95/p99, throughput, errors/stalls, memory peaks and headroom against the predeclared limits; retain slow intervals and failures. Engine-only benchmarks do not replace application measurements. |
| FPC-09: host/storage failure | Run the selected host-reset or stronger storage-failure tier with the same installed candidate, workload and independent oracle. | Meet the repetition and verification criteria from the [external checklist](../testing.md#external-qualification-checklist). Identify which caches/failure domains were actually lost; a VM reset is not a physical disk power cut. Recheck every ACK and the DB after recovery. |

Use the [performance and memory procedures](../performance.md) to distinguish
process RSS from cgroup charge, engine latency from end-to-end application
latency, and an unavailable metric from zero. Re-run affected cases after
changing the package, storage class, configuration, workload envelope or limits.
Remote-provider and witness cases, and the longer fuzzing requirements, remain
on the external checklist when applicable; this matrix does not mark them done.

## Retain the outcome

Each case record contains the profile/candidate identifiers, start/end times,
fault point and observed fault, exit status, `pass`/`fail`/`inconclusive`/`skipped`,
measured values versus thresholds, ledger cutoff and verification output, and
artifact/log paths plus checksums. Record manual recovery steps and retries.
A skipped required case remains unqualified; choose any intentionally excluded
feature before the campaign and keep it outside the eventual supported scope.

Unit tests, simulated backing faults, package fixtures and systemd tests using
fake storage commands validate their own contracts. They do not execute the
kernel NBD/LVM/XFS or DB cases above, even if the fixture uses a real service
manager. Mark a case passed only with evidence from its declared installed
stack. Keep production approval pending until the selected profile's required
cases and acceptance limits are met.
