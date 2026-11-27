# Project status

This page is the single authoritative statement of what Maki supports today.
Other documents describe procedures or record evidence; when they disagree
with this page about the *current* state, this page wins and the other
document needs a fix. Dated reports under [`qualification/`](qualification/README.md)
describe what was true when they were written and never claim current state.

Last updated: 2026-11-27. External campaign evidence below runs through
2026-10-05; each report identifies the revision it exercised. See the
[remediation log](review-remediation.md) for implementation changes.

## Release state

| Item | Value |
|---|---|
| Version | `0.1.0` (workspace `Cargo.toml`). No final release; release candidates `v0.1.0-rc.<n>` are tagged only by the [release workflow](releasing.md#publishing-a-pre-release), as GitHub pre-releases |
| Production approval | **Pending.** No configuration of Maki is production-qualified |
| Recommended use | Evaluation and development on disposable Linux hosts |
| Primary platform | Debian 12 (bookworm), Linux 6.1, systemd 252, on Google Compute Engine VMs |
| Prebuilt packages | Only in GitHub pre-releases from the [release workflow](releasing.md#publishing-a-pre-release): a Debian 12 amd64 `.deb`, a RHEL 9 x86_64 `.rpm` and the source, unsigned, with `SHA256SUMS`; otherwise build from source ([Debian](getting-started/installation-debian.md), [RHEL 9](getting-started/installation-rhel.md)) |
| RHEL 9 | Not qualified: an RPM and an [installation guide](getting-started/installation-rhel.md) exist; CI checks the userspace in a CentOS Stream 9 container and, on every change, attaches through the kernel of a booted Rocky Linux 9 KVM guest with SELinux enforcing ([testing](testing.md#automated-ci)), a virtual machine on GitHub's hardware; Rocky Linux is a rebuild of RHEL, not RHEL, and no RHEL host, bare-metal host or campaign has run |

## Volume formats

| Format | Selection | Status |
|---|---|---|
| Superblock envelope v2, mirrored durable proofs | Default for `maki volume create` | Current default; all scoped campaigns below used it unless noted |
| Envelope v3 with durable TRIM and space reclamation | `maki volume create <config> --discard` | Implemented; scoped GCE whole-instance-reset campaigns passed (2026-09-20, and 2026-10-03 after the R5 fixes), kernel `fstrim` reclaimed backing space through XFS/LVM/NBD, and scoped PostgreSQL 15 and 17 crash and lifecycle campaigns passed ([details](space-reclamation.md)) |
| Rollback-protected backing (local witness) | `[backing.rollback_protection]` on a new volume | **Experimental.** Focused test suites only; not campaign-qualified ([details](rollback-protection.md)) |
| Rollback-protected backing (remote witness V2) | `[backing.rollback_protection.remote]` on a new volume | **Experimental.** TLS 1.3 mutual authentication, authority/wire v2 with private session capabilities, durable compare-and-swap, separate writer namespaces, automatic safe namespace GC and administrator restore/enrollment recovery; optional etcd-quorum replication and identity-pinned frontend failover; automated fault, real-TLS and local 3-member etcd tests, no external campaign ([service guide](remote-witness-service.md)) |
| Legacy envelope v1 | Existing volumes only | Read-only checks with a warning; writable recovery is refused; migrate through [durable recovery](durable-recovery.md) |

There is no in-place format upgrade between envelopes.

## Crypto providers

| Provider | Status |
|---|---|
| `local-aes-gcm-siv` | Supported and used by the local-provider kernel NBD/LVM/XFS campaigns; authenticated and context-bound |
| `local-aes-xts` | Supported; no authenticated integrity, wrong-key detection only through the key canary; not used in external campaigns |
| `remote-http` | Supported; scoped campaigns against a reference provider (loopback, then cross-host TLS 1.2/1.3, mTLS, bearer, failover, credential and CA rotation, shipped sandbox and provider-host reset; SQLite and PostgreSQL 17). No commercial vendor endpoint qualified |
| `remote-websocket`, `remote-grpc` | Supported; scoped campaigns against a reference provider, single-host and cross-host (TLS 1.2/1.3, mTLS, failover, total-outage stall and resume, restart, deep check, shipped sandbox and provider-host reset; PostgreSQL 15 over gRPC). No commercial vendor endpoint qualified |

## Deployment topology

The attachment topology covered by packaged recovery campaigns is one whole
NBD device as a single LVM PV, one VG, one XFS data LV, attached through
`maki-attach` with `fs_uuid` and
`[lvm_identity]` pins, under the packaged systemd lifecycle. Everything else is
enumerated, with its status, in the [support matrix](deployment/support-matrix.md).

## Databases and workloads

| Workload | Status |
|---|---|
| SQLite WAL (`synchronous=FULL`) | Scoped campaigns: installed lifecycle with nbdkit crashes, fresh-host restore, package upgrade, migration, provider outage |
| PostgreSQL 15 (checksums, `fsync`, `synchronous_commit`, `full_page_writes` on) | Scoped postmaster-`SIGKILL` crash and lifecycle campaigns on Debian 12, including v3 discard under load and a remote gRPC reference provider; `pg_amcheck` passed. Production profiles and long runs open |
| PostgreSQL 17 (same durability settings) | One scoped crash and packaged LVM lifecycle campaign on Debian 13 over a per-item HTTP reference provider, with `fstrim` and an endpoint outage under load; `pg_amcheck` passed. Production profiles and long runs open |
| Other databases and object stores | Not tested |

## Failure-injection evidence

| Tier | Status |
|---|---|
| Deterministic simulation (model, crash, fault, chaos, fuzz) | Passing in CI and release gates |
| Native nbdkit process kill, cgroup CPU/freeze/OOM | Scoped campaigns passed; constrained-recovery RSS measured for one profile |
| Firecracker guest loss, GCE whole-instance hard reset | Scoped campaigns passed (v2 and v3) |
| Remote provider-host hard reset | One scoped Debian 12 cross-host campaign passed for HTTP, WebSocket and gRPC; sequential fsync'd files, reference provider, approximately 12–20 s stalls |
| Physical power loss, QEMU power cuts, 72-hour mixed soak | **Open** |

The October boundary-review fixes are merged in `main`. The scheduled
[CI run 39109347979](https://github.com/seo-rii/maki/actions/runs/39109347979)
passed all six jobs on `e50bcea0857de5750ef8ae4f06d40bbb51dfce0d`, including
both Windows toolchains, release/native gates and real three-member etcd
qualification. The [boundary review record](review-boundaries-2026-10-15.md#main-verification--2026-10-19)
maps the original findings to corrections and their remaining scope.

## Runtime cache settings

An enabled read cache accepts byte-limit and TTL updates through the control
socket and `maki reload <config> cache --max-bytes N [--ttl DURATION]`.
Omitting TTL preserves it. Invalid fields leave both settings unchanged;
cache mode and payload verification still require a restart.
See [cache reload](operations.md#growth-and-cache-reload).

## Known limitations

- Linux backing files and locks must be regular files with one hard link.
  Hardlink-based backing copies are unsupported while the extra links exist.
  The check occurs on open; later link creation and already-open handles are
  outside its protection ([namespace boundary](architecture.md#backing-namespace)).
- Maki's space reservation (`posix_fallocate`) holds only where the backing
  filesystem overwrites allocated blocks in place. Backing files must not
  share extents with reflink copies (`cp --reflink`, and coreutils 9 `cp` by
  default on XFS or btrfs) or btrfs snapshots, and a copy-on-write backing
  filesystem (btrfs with its default copy-on-write data, ZFS) is unsupported:
  there an overwrite needs new space and can fail with ENOSPC despite the
  reservation. btrfs with NOCOW backing files is not qualified. Maki detects
  neither shared extents nor copy-on-write
  ([backing store](deployment/support-matrix.md#backing-store-below-maki),
  [copy-on-write filesystems](deployment/support-matrix.md#copy-on-write-filesystems)).
- Admission limits cover Maki-owned engine work and plugin handles.
  nbdkit owns sockets and threads before plugin open; these limits do not
  establish a process-wide cap on negotiation resources.
- Dirty-XFS full stop, repeated recovery timeout/OOM convergence, and
  interruption at every attach step still need campaigns on the current
  integrated revision. Shutdown procedures now allow unmount writes before
  drain. Failed attach startup can schedule the workload recovery coordinator,
  and completed recovery work can extend the daemon startup deadline; neither
  establishes installed-stack convergence or persistent replay progress across
  repeated interruptions. Follow the [first production campaign](deployment/first-production-candidate.md)
  and [review scope](review-boundaries-2026-10-15.md#known-operational-items).
- Default v2/v3 backings cannot detect restoration of an older, internally
  valid volume image (historical rollback). Only the experimental
  rollback-protected backing addresses this, and it is not qualified.
- On Linux, a backing root the user may not write (a read-only mount, for
  example) is checked and inspected read-only; on other platforms every root
  opens as before. A read-only check cannot show that what it reads is on
  disk, or make the rewrites and repairs recovery makes, so its deep verdict
  is `unproven`, never `clean`. A rollback-protected backing whose root or
  witness directory the user may not write, and every one with a remote
  witness, is read through a read-only view that
  authenticates it as attach does, writes nothing and asks a remote
  authority only to inspect, three times per command (four for `check
  --deep`) however large the volume; it takes the writer's locks shared, so
  these commands refuse such a backing while a daemon holds it
  ([checking a backing that cannot be written](operations.md#checking-a-backing-that-cannot-be-written)).
  With a remote witness, attach refuses a configuration that does not match
  the volume before it claims a writer at the authority.
- `local-aes-xts` returns garbage rather than an error for a wrong key once
  the canary check is bypassed by an empty volume; use `local-aes-gcm-siv`.
- Remote transport libraries may keep plaintext copies outside `SecretBuffer`,
  and stack temporaries of the local cipher implementations are outside the
  `secure-buffers` page lock ([transport memory](transport-memory.md)).
- A gRPC endpoint whose TLS 1.3 server refuses the client certificate is
  reported with a retryable status (`grpc status Unknown`, `Cancelled` or
  `Unavailable`), not as a TLS authentication failure: the refusal arrives
  after the handshake and the HTTP/2 library does not keep the TLS error
  ([provider error signals](configuration.md#provider-error-signals)).
- An endpoint address that does not answer still costs time on every
  connect. All three remote transports try the other address family 300 ms
  after the first, so a dead IPv6 route before a live IPv4 address costs
  about 300 ms. Within a family each transport gives each address a share
  of the timeout, so a dead address before a live one of the same family
  (two IPv4 addresses, say) costs its share: half the timeout for two. With
  less than 600 ms of a connect left, the WebSocket transport starts the
  other family halfway to its deadline instead, and with a `timeout` under
  600 ms the gRPC transport halfway through it. The HTTP transport cannot:
  the 300 ms is set in hyper-util's connector, which reqwest builds and
  offers no way to change or to replace (the
  [remote HTTP mapping](configuration.md#remote-http-mapping) says why), so
  with an HTTP `timeout` of 300 ms or less the other family is never tried
  when the first one does not answer, and below 600 ms it has less than
  half of the time; such a `timeout` is accepted with a warning. The HTTP
  shares are fixed, as in the gRPC connector: each of a family's `n`
  addresses may take `timeout / n`, however soon the one before it failed,
  so one refused at once does not pass its time on, and a live address
  slower to accept the connection than its share is given up. The tests
  reach IPv6 only on loopback, and a route that drops packets only as a
  packet filter in a private network namespace (a root-only test).
- Recovery uses a 1 MiB replay grouping target; a permitted single record
  can be larger. Live replay payload storage is bounded by 1 MiB plus
  `max_ciphertext_size`, with record/index metadata and shard maps/catalogs
  additional ([recovery memory](durable-recovery.md)). The journaled overlay is
  bounded by `limits.max_overlay_bytes`/`max_overlay_entries`, but a total-RSS
  bound for arbitrary geometry, provider and cache settings is unestablished.
  Opt-in `security.memory_budget` now checks an explicitly measured cgroup-v2
  ceiling, visible ancestor headroom and memlock before recovery and READY.
  The service manager applies the kernel limit; this does not establish a
  universal minimum RAM requirement or reserve runtime headroom
  ([configuration](configuration.md#measured-memory-budget)).
- The volume's XFS filesystem is mounted `nosuid,nodev`; workloads that need
  setuid programs or device nodes on it are not supported.
- The R5 changes passed one scoped GCE campaign on 2026-10-03
  ([record](qualification/r5-hardware-validation-2026-10-03.md)): ten v3
  discard resets, kernel `fstrim` reclamation through XFS/LVM/NBD, the
  `nosuid,nodev` mount, attach-config ownership, and the packaged quick start
  under the `maki@.service` sandbox. A further campaign that day ran
  PostgreSQL 15 crash and lifecycle tests on a v3 volume with `fstrim` under
  load, and three lifecycles under the adopted syscall filter
  ([record](qualification/database-discard-pressure-validation-2026-10-03.md)).
- All three remote transports ran under that filter on 2026-10-04, each
  with mTLS, endpoint failover, a total-outage stall and resume, `fstrim`
  and a restart, with no syscall outside `@system-service`
  ([record](qualification/remote-transport-syscall-filter-validation-2026-10-04.md)).
  PostgreSQL 15 then passed its crash and lifecycle scenario over remote gRPC,
  with an endpoint outage under load, under the packaged unit including
  `MemoryDenyWriteExecute=yes`
  ([record](qualification/remote-database-zero-mdwe-validation-2026-10-04.md)).
- Debian 13 (systemd 257, glibc 2.41, Linux 6.12) passed a scoped campaign
  with all three remote transports under the shipped sandbox, with latency
  and packet loss, and NBD zeroing
  ([record](qualification/debian13-remote-transport-validation-2026-10-04.md)).
  It needs `fc8d697` or later; it ran with nbd-client 3.27 built from source,
  which the helper no longer uses (see below). That
  campaign's per-item HTTP mapping was slow under latency (one round trip
  per 4 KiB unit, in sequence); a request's units now go out concurrently
  (R5-039). On Debian 13 a per-item HTTP volume then did 0.61 MiB/s of
  sequential direct I/O with 10 ms ± 5 ms of loopback latency and
  0.16–0.17 MiB/s with 1 % loss added; prefer a batched mapping. PostgreSQL
  17 passed its crash and lifecycle scenario over that mapping with the
  packaged `maki-attach` LVM lifecycle
  ([record](qualification/debian13-postgresql-http-validation-2026-10-05.md)).
- With client and provider on separate VMs and the provider reached by its
  internal DNS name, all three remote transports passed under the shipped
  sandbox on Debian 12
  ([record](qualification/cross-host-sandbox-validation-2026-10-05.md)).
  Hard resets of that provider host during fsync'd writes stalled the
  writer for 12–20 s per transport, with no failed write and no lost
  acknowledged data
  ([record](qualification/provider-host-reset-validation-2026-10-05.md)).
- Below the backing's emergency reserve plus checkpoint headroom, writes are
  refused. A filesystem on the volume can then neither delete files nor run
  `fstrim` (XFS returned EIO for both); recover by freeing space on the
  backing filesystem. Raw discards need no checkpoint headroom and are still
  admitted while free space covers the emergency reserve and their journal
  records.
- Automatic dead-daemon cleanup supports the pinned single-PV/single-data-LV
  XFS topology. A sidecar LV passed attach/detach, but multi-mapping and other
  device-mapper recovery layouts fail closed and need operator diagnosis
  ([storage recovery limits](storage-recovery.md#remaining-recovery-limits)).
  A daemon that stops while an attach is between LVM activation and its
  mapping record, with the helper gone as well, leaves an unused mapping that
  takes [one manual step](operations.md#interrupted-activation-after-the-daemon-stopped)
  to remove.
- No NBD client package is needed: the privileged helper negotiates with the
  daemon's socket and connects the kernel device over netlink itself, and
  refuses an export without FLUSH and FUA. Every external campaign that
  attached a kernel NBD device did so through nbd-client (3.27.1 where the
  report names the version; 3.24 in the 2026-09-02 privileged run) and
  predates the helper's own connect; the others attached none. Unit
  tests, tests against a real nbdkit and Maki's plugin, a root-only kernel
  test in CI (whose runners load the `nbd` module) and CI's whole attachments
  (next item) cover the helper's connect; no external campaign has run it yet.
- On every change, CI's `kernel-lifecycle` job drives whole attachments
  through the kernel NBD, udev, device-mapper, LVM and XFS of a disposable
  GitHub Ubuntu runner, not the Debian 12 primary platform
  ([testing](testing.md#automated-ci)). The privileged runner attaches, writes
  and fsyncs data, and detaches while another process holds the device open;
  it requires that the detach returned only after that process had begun to
  close the device, which keeps showing the connection until then, so the
  detach must have waited (AUD-197). It attaches again and reads the data
  back, then kills nbdkit under the mount, cleans up without it, starts a new
  nbdkit and attaches a third time. The Debian guide's install steps, the
  quick start and its first-volume bootstrap (AUD-199) then run as written on
  the package built from the same commit, under systemd with the installed
  units, including the attach unit's `ExecStop` cleanup on two planned stops.
  In the job's runs whose logs are kept the killed daemon's device still
  showed its connection, so that cleanup took cleanup's detach path. The job
  now also kills nbdkit a second time and disconnects and releases its device
  by hand so that cleanup takes its disconnected recovery (AUD-203), captures
  what the helper's readers parse on the attachment, runs the quick start
  with the bootstrap stopped once (at `mkfs.xfs`, and at `vgchange`) and
  continued from its record, and stops three volumes together, each device
  held open for 10 s, recording how long each stop takes. These additions
  ran on GitHub's runner VMs on 2026-11-27 at commits a6c2006, f933c7c,
  8b9ef4d and 31b7ef8 of #413 and at a2db40e, the head that merged; the
  privileged runner and both stopped quick starts passed in each. In the runs
  whose logs are kept (all but a6c2006's; Linux `7.0.0-1020-azure`, and
  `7.0.0-1016-aws` at 8b9ef4d) the device still showed the connection after
  the disconnect, with XFS mounted on the LV and again
  after the unmount, and showed none once the LV's mapping was removed: the
  mapping keeps the connection's attributes (the mount sits on the mapping,
  so its own effect is not told apart); cleanup then took its disconnected
  recovery and left nothing. The stop together failed in the first three
  runs on its own reading of systemd's unit timestamps: at a6c2006 and
  f933c7c, with the same driver, it read them before the attach units had
  stopped (as f933c7c's log shows), at 8b9ef4d after systemd had forgotten
  the stopped units; it now reads the journal. Their journals
  show the stops queued one after another on the global attach lock: about
  10.2, 20.3 and 30.5 s after they began at f933c7c, and about 30.5 s from
  the first stop's start to the last one's end at 8b9ef4d (whose driver
  found every unit stopped after 30.678 s). Detach and cleanup now wait for a held-open device without the
  attach lock (AUD-197, #410), and at 31b7ef8, which has that change, the
  stop together passed: the three stops took 10.183, 10.246 and 10.310 s,
  about the 10 s hold each, and every attach unit had stopped 10.388 s after
  the request; at a2db40e they took 10.153 to 10.214 s, and 10.488 s in
  all. That is local-provider volumes on GitHub's runner kernels, and nbdkit
  is killed only while the filesystem is idle after a sync. How often
  something holds a device open at a detach on a production host has not
  been measured.
- On every change, CI's booted-host jobs boot Debian 12's generic cloud image
  (Debian's standard kernel, Linux 6.1) and Rocky Linux 9.9's GenericCloud
  image with SELinux enforcing as KVM guests on GitHub runner VMs, a fresh
  guest per suite, with images pinned by digest
  ([testing](testing.md#automated-ci)). In one guest per distribution, as
  root on its own kernel, systemd and udev, the installation guide's host
  steps (the RHEL guide's on Rocky Linux), the quick start and the
  first-volume bootstrap run as written with the package built from the
  commit on that distribution; in another, as the guest's user `ci` with
  passwordless sudo, the privileged runner's lifecycle runs with that
  package's binaries. On Rocky Linux the job requires, after either suite,
  SELinux still enforcing, auditd active and no AVC that names Maki or an
  NBD device, and after the guides the nbdkit of `maki@` in
  `unconfined_service_t` and the file labels the RHEL guide lists. These are
  virtual machines on GitHub's hardware with QEMU's user-mode network, not
  bare-metal hosts, Rocky Linux is a rebuild of RHEL rather than RHEL, and
  the jobs use the local provider, one volume at a time and no power loss.

## Where the evidence lives

- Automated coverage and release gates: [testing](testing.md).
- Dated external campaigns and reviews: [qualification index](qualification/README.md).
- Review findings and fixes: [remediation log](review-remediation.md).
- Remaining external checks before any production approval:
  [external qualification checklist](testing.md#external-qualification-checklist).
