# Privileged Linux Validation

This runbook closes the safe, host-dependent part of Maki's Linux data-path
qualification. It drives a disposable Maki export through kernel NBD, LVM,
XFS, fio, and SQLite, while keeping the chosen device and all artifacts easy
to audit.

Related documentation: [Operations](operations.md) ·
[Testing and qualification](testing.md)

The runner is intentionally conservative: it accepts only `/dev/nbdN`,
requires the same path again as an explicit wipe confirmation, and stops if
the device is already connected, mounted, or held by another block device. It
does not unload kernel modules and never targets a physical disk.

## Scope

The automated run checks:

- release builds and the nbdkit `plugin_init` export;
- nbdkit/libnbd negotiation and duplicate-attach exclusion;
- the nbdkit process's unprivileged UID, `NoNewPrivs`, and empty effective
  capability set;
- denial of the protected socket to an unrelated user;
- kernel `/dev/nbdN` attachment and exported geometry;
- denial of an NBD disconnect ioctl to the invoking unprivileged user;
- raw-device fio with CRC32C verification and periodic `fsync`;
- disposable LVM and XFS creation;
- the real `maki-attach` attach, read-only verify, and convergent cleanup paths,
  including a second idempotent cleanup;
- root-owned mode-`0600` attach configuration and exact PV/VG/LV UUID pins;
- unprivileged fio through the mounted XFS filesystem; and
- a SQLite WAL checkpoint with `synchronous=FULL` and `integrity_check`.

The run does **not** force a daemon crash, send `SIGKILL`/`SIGSEGV`, induce an
OOM, interrupt power, test a real disk, or modify installed Maki systemd
units. Those scenarios need an isolated destructive-test host and are outside
this safe runner.

## Run

The current helper requires nbd-client 3.27.0 or later built with netlink and
backend-identifier support. Debian 12's stock nbd-client 3.24 is too old, and
`--install-missing` does not replace an already installed old client. Build or
install a qualified version before running the suite; a source build also needs
`autoconf-archive`. The configured block-device path remains `/dev/nbd15`.
Internally, current netlink nbd-client commands receive the kernel name
`nbd15`, while block tools continue to receive `/dev/nbd15`.

Use a high-numbered, dedicated NBD device. The following command installs the
missing Debian packages, caches sudo authorization interactively, and then
starts the validation under `nohup`:

```bash
cd /home/seorii/dev/hancomac/maki
./scripts/privileged-linux-validation.sh \
  --background \
  --install-missing \
  --device /dev/nbd15 \
  --confirm-wipe /dev/nbd15
```

Do not substitute `/dev/sd*`, `/dev/nvme*`, a loop device, or a production NBD
device. The script rejects non-NBD paths, but the operator remains responsible
for choosing a disposable, unused NBD index.

On hosts without a suitable `/data` filesystem, add `--work-root` pointing to
a writable filesystem with at least 768 MiB free. The disposable export is
512 MiB; the runner removes its backing tree during normal cleanup.

For a read-only dependency preview, run:

```bash
./scripts/privileged-linux-validation.sh --preflight --device /dev/nbd15
```

## Logs and completion

Every run creates a mode-`0700` directory below `~/logs` and mode-`0600`
artifacts within it. A stable symlink points to the newest run:

```text
~/logs/maki-privileged-validation.latest/
├── run.log
├── status
├── nbdkit.log
├── fio-raw.json
├── fio-xfs.json
├── sqlite.txt
├── maki-attach-plan.txt
├── maki-verify-before-workload.txt
├── maki-verify-after-workload.txt
├── maki-cleanup.txt
├── maki-cleanup-idempotent.txt
└── maki-check.txt
```

`status` is finalized at the logical end of the run. `state=passed` and
`exit_code=0` mean every check and cleanup step succeeded. If it reports
`state=failed`, keep the run directory and inspect the bounded end of
`run.log` plus the relevant component log before retrying.

The latest log path on this host is:

```text
/home/seorii/logs/maki-privileged-validation.latest/run.log
```

## Cleanup guarantees

The exit trap attempts, in order, to unmount the test filesystem, deactivate
the uniquely named test VG, disconnect only the NBD connection created by the
run, terminate nbdkit normally with `SIGTERM`, remove the unique `/run/maki`
child directory, and delete only the `mktemp` work tree.
It also removes the per-volume `/run/maki-control` directory and the temporary
root-owned attach configuration created by the run.

If nbdkit does not exit after normal termination, the runner deliberately does
not escalate to `SIGKILL`; it fails and preserves the backing tree so an
operator can inspect the live process safely.

## Combined Debian 12 GCE crash result — 2026-09-13

Revision `8bf0e941bd3501b972850240fb1050fbc2a90c0b` passed 29 checks on a
disposable `n2-standard-4` host using the Debian image, kernel, and native tool
versions listed in the safe-run result below. A one-use qualification harness
extended the tracked runner with an actual nbdkit crash and Docker SQLite ACK
oracle; it did not change the tracked runner's non-crashing contract. The
[Linux and Windows CI run](https://github.com/seo-rii/maki/actions/runs/34712284092)
for the same revision also passed.

The run attached a 512 MiB local AES-GCM-SIV export through kernel NBD to a
single-PV, single-LV LVM/XFS filesystem with all administrator UUID pins. A
new `rprivate` Docker container committed 32 acknowledged rows using SQLite
WAL and `synchronous=FULL`; the external ACK ledger and its directory were
fsynced outside the Maki filesystem. The actual nbdkit PID then received
`SIGKILL` and returned wait status 137. The kernel connection remained connected
after server death, and the read-only identity gate returned success because it
checks kernel identity and mount topology rather than data-path liveness.

`maki-attach cleanup` first received a nonzero result from LVM against the dead
server, then used the completed recovery proof to remove the exact closed
device-mapper target and disconnect NBD. After a new nbdkit process started,
the helper reattached and verified the same storage. A distinct `rprivate`
Docker container recovered all 32 acknowledged rows byte-for-byte against the
external ledger and reported `integrity_check=ok`. Final cleanup, a second
idempotent cleanup, disposable LVM removal, clean nbdkit shutdown, and offline
`maki check` all passed.

The direct device-mapper fallback is deliberately limited to one recorded
target mapping whose current name, UUID, major/minor, dependency, open count,
mount state, and NBD connection identifier match the proof. It uses one plain
`dmsetup remove`, without force, deferred removal, or retry flags. Multi-LV and
internal thin/cache/RAID mappings, open targets, changed topology, an unknown
holder, command timeout, or backend identity change fail closed and preserve
the trusted record.

The complete evidence archive and its SHA-256 manifest are under
`/home/seorii/logs/maki-gcp-combined-20260913-evidence`. Before deletion the
guest had no NBD connection, holder, mount, Maki device-mapper target, nbdkit
process, test container, or test LV. The instance and auto-delete boot disk
were deleted; fresh project queries returned zero `maki-*` instances and disks,
and an exact disk lookup returned 404.

This is one abrupt userspace-server failure in one local-provider, single-LV
topology. It does not combine the installed packaged systemd recovery graph,
does not test a whole-VM or physical power cut at the same time as the database,
and does not qualify multi-LV/internal mappings, remote providers, other
databases, repeated crash cycles, or long-duration load.

## Safe Debian 12 GCE validation result — 2026-09-13

The safe suite passed all 22 checks with exit code 0 at revision
`5a3bef69aa4980c6783e177c44e6e0b5b7f286f0`; its
[Linux and Windows CI run](https://github.com/seo-rii/maki/actions/runs/34707982492)
also passed. The disposable target was a GCE `n2-standard-4` using
`debian-12-bookworm-v20260908`, Linux `6.1.0-53-cloud-amd64`, Rust 1.98.1,
nbd-client 3.27.1 (source revision
`f96f7fca3b37f4254c26c95f5c6c9dae70e030a1`), nbdkit 1.32.5, LVM 2.03.16,
XFS tools 6.1.0, fio 3.33, and SQLite 3.40.1.

The 512 MiB `/dev/nbd15` run passed rootless nbdkit isolation, exact kernel NBD
geometry, raw CRC32C fio, a single-PV LVM/XFS topology with all administrator
UUID pins, the real attach and verify paths, unprivileged XFS fio, SQLite WAL
with `synchronous=FULL`, a full checkpoint and `integrity_check=ok`, the real
cleanup path, a second no-record cleanup, clean daemon shutdown, and the
offline Maki check. Cleanup removed the LVM metadata and runtime artifacts.
The instance and its auto-delete boot disk were then deleted; fresh project
queries returned zero `maki-*` instances and zero `maki-*` disks.

This is a non-crashing smoke test with one local AES-GCM-SIV provider. nbdkit
ran through `setpriv`; the run did not exercise the installed `maki@.service`
sandbox or a persistent `maki` account. It does not prove database ACK survival
through a storage crash, real NBD/LVM/XFS recovery inside the packaged systemd
lifecycle, remote-provider behavior, or long-duration operation.

## Historical Debian 12 validation result — 2026-09-02

The safe privileged suite passed on a Debian 12 KVM host at revision
`0c4a44a4d2e4ae5f468afad28e49e6fa945a23ea` with Linux
`6.1.0-52-cloud-amd64`. The run completed 19 checks with exit code 0.

| Check | Result | Evidence |
|---|---|---|
| Release binaries and nbdkit ABI export | Pass | `maki`, `maki-attach`, and `maki-nbdkit` release build; exported `plugin_init` |
| Userspace negotiation | Pass | nbdkit 1.32.5 and libnbd 1.14.2 opened the 512 MiB export |
| Runtime privilege boundary | Pass | Non-root effective UID, `NoNewPrivs=1`, `CapEff=0`; unrelated user denied |
| Duplicate attach | Pass | Second process reported `VOLUME_ALREADY_ATTACHED` |
| Kernel NBD | Pass | nbd-client 3.24 attached `/dev/nbd15`; unprivileged disconnect was denied |
| Raw fio | Pass | 64 MiB written and verified, CRC32C, 511 sync I/Os, fio error 0 |
| LVM and XFS | Pass | Disposable PV, VG, 384 MiB LV, and XFS created successfully |
| `maki-attach` lifecycle | Pass | LVM activation, XFS mount, unmount, deactivation, and NBD disconnect |
| Filesystem fio | Pass | 64 MiB written and verified as an unprivileged user, CRC32C, 511 sync I/Os, fio error 0 |
| SQLite smoke | Pass | WAL, `synchronous=FULL`, checkpoint completed, `integrity_check` returned `ok` |
| Offline consistency | Pass | Clean nbdkit shutdown; `maki check` passed with 13 shards |

The runner removed the disposable LVM metadata, disconnected the NBD device,
stopped nbdkit normally, and deleted the backing work tree. Independent checks
found no NBD connection, block holders, mounts, test VGs, or remaining nbdkit
processes. Two empty `/run/maki/privval-*` directories remained because stale
Unix socket removal was missing from the first runner version; the sockets were
removed manually, and the cleanup path was corrected to remove them and fail
the run if the runtime directory cannot be removed.

This result qualifies the safe kernel-NBD, LVM, XFS, fio, helper, privilege,
and SQLite smoke paths on the stated host. It does not qualify forced process
crashes, OOM behavior, power loss, production systemd installation, PostgreSQL,
ClickHouse, MinIO, or long-duration workloads.

## Relationship to other qualification tiers

This run supplies privileged kernel-NBD, filesystem, and safe host privilege
evidence. It is not evidence for destructive database crash campaigns,
hard-power-loss testing, or long-duration mixed-workload qualification; those
remain separate, isolated-host gates described in
[Testing and qualification](testing.md).
