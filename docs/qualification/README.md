# Qualification evidence

Everything in this directory is a **dated record**: what a specific revision
did on a specific disposable environment, and what it deliberately did not
do. Reports never claim current state. For the current state read
[status](../status.md); for the automated tiers and the release gates read
[testing](../testing.md); for the review findings and their fixes read the
[remediation log](../review-remediation.md).

## Campaign reports

| Date | Report | Revision | What it covered |
|---|---|---|---|
| 2026-09-02 | [Rootless Linux validation (Debian 12/KVM)](native-linux-validation-2026-09-02.md) | `8f8b13d` | Workspace suites, plugin ABI probe, nbdkit/libnbd/fio userspace data path; no kernel device |
| 2026-09-13 → 09-17 | [Privileged Linux validation](privileged-linux-validation.md) | `5a3bef6`, `448c0b2` | Runbook plus results: kernel NBD, single-PV LVM/XFS, pinned attach/verify/cleanup, fio, SQLite; installed systemd graph with two nbdkit `SIGKILL` recoveries and one fail-closed cleanup |
| 2026-09-12 | [Native process and cgroup faults](cgroup-fault-validation-2026-09-12.md) | `e894ae5`, follow-up `733833c` | CPU throttling, freeze/resume, `SIGKILL`, workload OOM at 32/96/192 MiB; recovery memory limit found and later bounded |
| 2026-09-12 | [Firecracker guest crash](firecracker-validation-2026-09-12.md) | — | 20 abrupt microVM kills with cold-boot authenticated readback; L1 host stayed alive |
| 2026-09-13 | [GCE whole-instance reset](gce-reset-validation-2026-09-13.md) | — | 10 hard resets removing RAM, kernel and page cache; 160 acknowledged versions retained |
| 2026-09-17 | [Fresh-host backing restore](fresh-host-restore-validation-2026-09-17.md) | `ece7e39` | Graceful export, source VM deleted, restore on a new VM, continued writes and restart |
| 2026-09-18 | [Remote HTTP provider database faults](remote-provider-db-validation-2026-09-18.md) | `c385c99` | Two loopback authenticated providers, single-endpoint failover, total outage stall/resume, SQLite ledger |
| 2026-09-18 | [PostgreSQL process crash](postgresql-crash-validation-2026-09-18.md) | `5f50354` | PostgreSQL 15.19 with checksums, postmaster `SIGKILL` under pgbench, WAL recovery, four `pg_amcheck` runs, Maki restart |
| 2026-09-18 | [Physical checkpoint-space reservation](physical-reservation-validation-2026-09-18.md) | `3cac300` | ext4 block allocation before FUA acknowledgement; ENOSPC refusal with unchanged journal |
| 2026-09-19 | [Debian package, topology and migration](package-topology-migration-validation-2026-09-19.md) | `3cac300` | Clean install and upgrade, two simultaneous volumes with a sidecar LV, fail-closed multi-mapping and foreign backend, SQLite DB-native and legacy-v1 migration |
| 2026-09-19 | [Constrained recovery RSS](recovery-rss-validation-2026-09-19.md) | `733833c` | Four OOM tails recovered at 48/64 MiB; nbdkit `VmHWM` ≤ 11,415,552 bytes for that profile |
| 2026-09-19 | [Cross-host TLS reference provider](cross-host-tls-provider-validation-2026-09-19.md) | `47058d2` | Private VPC, TLS 1.2/1.3, mTLS and bearer refusal, two-host failover, outage resume, restart readback |
| 2026-09-19 | [Credential rotation and key migration](credential-rotation-key-migration-validation-2026-09-19.md) | `bdb9113` | Stopped bearer/mTLS client rotation, old-credential refusal, DB-native restore into a distinct-key volume |
| 2026-09-19 | [Server CA and endpoint rotation](server-ca-endpoint-rotation-validation-2026-09-19.md) | `da89ae3` | Private-CA overlap and removal, server-certificate refusal, same-key endpoint-address replacement |
| 2026-09-20 | [GCE discard/reset (v3)](gce-discard-reset-validation-2026-09-20.md) | `f5bde3e` | Ten whole-instance resets against an opt-in v3 discard volume with the local provider |

Unattended repetition of the storage test suites on a local host is described
in [background storage regression runs](../background-storage-validation.md).

## Reviews and readiness records

| Date | Document | Nature |
|---|---|---|
| 2026-09-02 | [Independent code and architecture review](historical-reviews/external-review-2026-09-02.md) | External review of the `maki-main.zip` snapshot: 18 findings, production No-Go. Findings and fixes are tracked in the [remediation log](../review-remediation.md) |
| 2026-09-05 | [Project review](historical-reviews/project-review-2026-09-05.md) (Korean) | Assessment of `8b06c53`: nine further defects, all fixed with TDD regressions ([log](../review-remediation.md#follow-up-review-2026-09-05)) |
| 2026-09-08 → 09-20 | [Operational readiness review and R3 fix record](historical-reviews/production-readiness-review-2026-09-08.md) (Korean) | Running record of the R3 review, its fixes, snapshot verifications and the operational approval decision (still pending) |

## Review history in brief

This section preserves the summary that used to open the project README.

| Review | Outcome |
|---|---|
| 2026-09-02 external review (18 findings) | All addressed with regression tests; see the [remediation log](../review-remediation.md) for scope and residual external validation |
| 2026-09-03 sanitizer and randomized-suite pass | Debug-build invariant checkers plus fuzz, stress, corruption and model suites; five findings (S-01 data read as zeros after an A/B fallback, S-02 overlay accounting, S-03 stale durable mark, S-04/S-05 recovery under out-of-order sector persistence) fixed with regression tests ([log](../review-remediation.md#sanitizers-and-randomized-suites-2026-09-03)) |
| 2026-09-03 second audit (core, crypto, operations) | 27 confirmed findings fixed with regression tests, among them recovery accepting never-synced page-cache bytes after a process restart, HTTP redirects re-sending plaintext, the root helper following symlinks in the mount root, and detach disconnecting the wrong NBD device ([log](../review-remediation.md#second-audit-2026-09-03-core-crypto-layer-operational-layers)) |
| 2026-09-05 project review | Nine issues in A/B retries, request lifetimes, credentials and deployment boundaries, all with TDD fixes. The updated helper requires a new runtime layout and NBD backend identity support; follow the [upgrade procedure](../operations.md#upgrading-the-runtime-layout) |
| 2026-09-05 further reliability review | Reproduced and fixed partial journal writes, failed-writeback retries, cancelled crypto work, queue deadlines, NBD request limits, interrupted detach retries and control-socket permission races ([log](../review-remediation.md#further-reliability-review-2026-09-05)) |
| 2026-09-07 supplementary review (R01–R08) | Safe attach rollback, live-topology grow checks, batch-scheduler admission bound, hung-helper lock timeout, journal hard-limit accounting ([log](../review-remediation.md#supplementary-review-2026-09-07-r01r08)) |
| 2026-09-07 comprehensive review (MAKI-001…050) | Code defects fixed with TDD regressions (self-test batching and integrity proof, remote-error redaction, fail-closed zram classification, per-type A/B read bounds, checked generation arithmetic); design, performance, deployment and capacity items tracked in the log's "Tracked, not closed in this pass" ([log](../review-remediation.md#comprehensive-review-2026-09-07-maki-001050)) |
| 2026-09-08 follow-up review (FUP-001…015) | Observation-based attach rollback, stale-record and live-mount grow guards, full remote-error redaction, plaintext-vs-ciphertext scheduler budgets, inconclusive-vs-proven self-test probes, volume-UUID context binding, first-attach canary verification, tighter A/B read bounds, in-flight byte budget validation ([log](../review-remediation.md#follow-up-review-2026-09-08-fup-001015)) |
| 2026-09-08 R3 readiness record | Supersedes the earlier remaining-work lists. `fb3da46` passed 812 workspace tests, nine release gates and Linux/Windows CI; `b3c5103` passed 865 tests and the release DB simulation; `2a3f023` added LVM preflight and native readiness and passed 901 tests, formatting, strict Clippy and CI. Production approval remains pending ([record](historical-reviews/production-readiness-review-2026-09-08.md)) |

## Writing a new report

- Name it `<topic>-validation-<YYYY-MM-DD>.md` and put it in this directory.
- Record the exact revision, image, machine type, kernel, tool versions,
  the workload, the failure injected, the oracle used, the result, and an
  explicit list of what was **not** covered.
- Add a row to the table above and, if the result changes what Maki claims,
  update [status](../status.md) and the
  [support matrix](../deployment/support-matrix.md) in the same change.
- Never edit a published report to reflect later fixes; add a dated follow-up
  section or a new report instead.
