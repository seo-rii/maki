# Privileged Linux Validation

This runbook closes the safe, host-dependent part of Maki's Linux data-path
qualification. It drives a disposable Maki export through kernel NBD, LVM,
XFS, fio, and SQLite, while keeping the chosen device and all artifacts easy
to audit.

Related documentation: [Operations](../operations.md) ·
[Testing and qualification](../testing.md)

The runner is intentionally conservative: it accepts only `/dev/nbdN`,
requires the same path again as an explicit wipe confirmation, and stops if
the device is already connected, mounted, or held by another block device. It
does not unload kernel modules and never targets a physical disk.

## Scope

Each foreground or background run exports the committed revision into its private
run directory before requesting sudo credentials. The worker and the Cargo build
use this source snapshot. Commit tracked changes before starting a run. The
snapshot excludes untracked files. `source-revision` records its commit ID, and
`artifact-sha256` records the hashes of the three binaries used in the run.
With `--prebuilt DIR` the run builds nothing and needs neither Cargo nor
rustc: it copies `maki`, `maki-attach` and `libmaki_nbdkit.so` from `DIR`
(which must hold all three) into its `target/prebuilt/`, runs those copies and
hashes them; `artifact-origin` names the directory. Nothing in the run then
ties the binaries to the snapshot's commit; CI's booted-host jobs take them
from a package built from the same commit
([testing](../testing.md#automated-ci)).


The automated run checks:

- release builds and the nbdkit `plugin_init` export;
- nbdkit/libnbd negotiation and duplicate-attach exclusion;
- the nbdkit process's unprivileged UID, `NoNewPrivs`, and empty effective
  capability set;
- denial of the protected socket to an unrelated user;
- kernel `/dev/nbdN` attachment and exported geometry;
- the kernel's denial of the helper's netlink `NBD_CMD_DISCONNECT` to the
  invoking unprivileged user (an `NBD_DISCONNECT` ioctl or `nbd-client -d` in
  the results below);
- raw-device fio with CRC32C verification and periodic `fsync`;
- disposable LVM and XFS creation;
- the real `maki-attach` attach, read-only verify, and convergent cleanup paths,
  including a second idempotent cleanup;
- root-owned mode-`0600` attach configuration and exact PV/VG/LV UUID pins;
- unprivileged fio through the mounted XFS filesystem;
- a SQLite WAL checkpoint with `synchronous=FULL` and `integrity_check`;
- what the helper's readers parse, captured as root after the first attach
  by `scripts/privileged_validation_capture.py` into `helper-outputs.json`:
  the output, exit status and standard error of LVM's `fullreport`, the
  `blkid` label and filesystem probes, `dmsetup info`, the LV's size and the
  mount source's UUID, each run with the helper's own arguments, an
  environment of only `PATH` and `LC_ALL=C` and no inherited descriptors;
  the device's nodes below `/sys/class/block` (the device, its partitions
  and every mapping above them) in the `helper_sysfs` fuzz input's line
  format; and the mount table. No key or payload is in it;
- 32 MiB written with `fsync` beside the database, and the SHA-256 of both;
- a `maki-attach detach` while `scripts/privileged_validation_opener.py`
  holds the device open: the opener reads whole blocks until a read fails
  with `EIO` (the kernel acknowledged the disconnect), keeps the device open
  two seconds more, writes that it is closing it, closes it, and requires
  that the device showed the connection until then and shows none after.
  The run requires that line to be there when the detach returns, so the
  detach must have waited for the close (AUD-197), and must succeed in one
  run; and
- a second attach with `init_sentinel = false`, the workload gate and the
  same hashes.

Each attach must show the mount, the attachment's backend identifier on the
device and the helper's attach record. After each detach, and after each
cleanup that ends an attachment, the mountpoint must be unmounted, the device
must have no holders, no `backend` or `pid` attribute and size 0, and the
attach record must be gone. The record is looked for as root, and a look that
fails stops the run. Without `--kill-daemon` the run then
ends the attachment with `maki-attach cleanup`. With `--kill-daemon` it
instead sends `SIGKILL` to its nbdkit under the mounted attachment (exit
status 137 required), requires `maki-attach cleanup` to release the
attachment without the daemon, removes the dead daemon's socket, starts a new
nbdkit on the same backing and configuration, which must negotiate, attaches
a third time and compares the hashes. It then kills that nbdkit too and
leaves its device showing no connection with the attach record in place, as
an operator could: `privileged_validation_nbd.py kernel-disconnect` sends the
kernel's `NBD_CMD_DISCONNECT` over netlink for the attachment's identifier
(which the helper's own `nbd-disconnect` refuses), and only while the device
still shows the connection does the run unmount XFS and then remove the LV's
mapping with `dmsetup remove`, logging what the device shows after each step
and waiting up to 15 s for the connection to go. `maki-attach cleanup` must
then retire the record by its disconnected recovery, a fourth attach after a
new nbdkit must compare the hashes, and the run ends with `maki-attach
detach`. The helper logs which path cleanup takes, and each cleanup must have
taken the one for what the device showed when it started: the detach path
for the attachment's connection, disconnected recovery for none. Either way
a second cleanup must then succeed without a record.

The run does **not** induce an OOM, interrupt power, test a real disk, or
modify installed Maki systemd units, and without `--kill-daemon` it forces no
daemon crash and sends no `SIGKILL`/`SIGSEGV`. Those scenarios need an
isolated destructive-test host; `--kill-daemon` kills only the run's own
nbdkit, twice, each time while the filesystem is idle after a sync,
disconnects and unmaps only the run's own device, and is meant for
disposable hosts such as CI's runner.

The duplicate-attach check uses the same backing, volume and crypto settings
with separate NBD and control socket paths. Its NBD path matches the second
nbdkit process's `-U` argument, so listener validation can reach recovery.
The check passes only when that process exits with startup-failure status 1
and reports the native startup error `VOLUME_ALREADY_ATTACHED`. A missing
plugin, invalid configuration, listener mismatch or process that stays alive
fails qualification. The duplicate configuration, stderr log and exit code
are retained as `duplicate-volume.toml`, `duplicate-nbdkit.log` and
`duplicate-nbdkit.exit` in the run directory; an unfinished process is stopped
by the normal exit cleanup and supplies no successful lock verdict.

## Run

The runner needs no nbd-client: the `maki-attach` it builds connects both the
raw export (`maki-attach nbd-connect`, outside any attachment) and the helper
phase's attachment with its own NBD handshake and netlink requests. The
configured block-device path remains `/dev/nbd15`; the helper addresses the
kernel device by its index.

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

CI's `kernel-lifecycle` job runs the runner on every change, in the
foreground on GitHub's Ubuntu runner, as the runner user (which has
passwordless sudo), with `--install-missing --kill-daemon --device /dev/nbd15
--confirm-wipe /dev/nbd15`, after loading the `nbd` module with the
parameters the runner asks for; see
[testing](../testing.md#automated-ci). It keeps the run directory, without
`source/`, `target/` and `build/`, in the job's `kernel-lifecycle-logs`
artifact. The booted-host jobs run it the same way in booted Debian 12 and
Rocky Linux 9 KVM guests (virtual machines on GitHub's hardware, not
bare-metal hosts; Rocky Linux is a rebuild of RHEL, not RHEL), as the guest's
user `ci`, with `--prebuilt` naming
the binaries taken from the package built from the commit (and
`--install-missing` on Debian only: on Rocky Linux the job installs the tools
with dnf); their `<guest>-guest-runner-logs` artifacts keep the run directory
the same way.

## Logs and completion

Every run creates a mode-`0700` directory below `~/logs` and mode-`0600`
log artifacts within it. Release artifacts and intermediate build files are
kept in that run's `target/` and `build/` directories. The build explicitly
selects the native Rust host target and these directories, overriding Cargo
target-directory and cross-compilation settings. Validation uses only those
release artifacts; allow disk space for a fresh release build on the log
filesystem. A stable symlink points to the newest run:

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
├── helper-outputs.json
├── lifecycle.sha256
├── detach-opener.txt
├── maki-detach.txt
├── maki-reattach.txt
├── maki-verify-reattach.txt
├── lifecycle-check-reattach.txt
├── maki-cleanup.txt                 (without --kill-daemon)
├── maki-cleanup-dead-daemon.txt     (--kill-daemon: this, the next eleven)
├── nbdinfo-after-kill.txt
├── maki-attach-after-kill.txt
├── maki-verify-after-kill.txt
├── lifecycle-check-restart.txt
├── kernel-disconnect.txt
├── maki-cleanup-disconnected.txt
├── nbdinfo-after-disconnect.txt
├── maki-attach-after-disconnect.txt
├── maki-verify-after-disconnect.txt
├── lifecycle-check-recovery.txt
├── maki-detach-final.txt
├── maki-cleanup-idempotent.txt
├── maki-check.txt
├── artifact-sha256
└── artifact-origin                  (built from the snapshot, or prebuilt DIR)
```

`nbdkit.log` holds the output of the three nbdkit processes of a
`--kill-daemon` run, the later ones after `--- a new nbdkit after the first
SIGKILL ---` and `--- a new nbdkit after the second SIGKILL ---` lines. The
lifecycle's helper output also goes to `run.log`, with each command's exit
status and duration, and a command that stops the run is named there with
its line number.

`status` is finalized at the logical end of the run. `state=passed` and
`exit_code=0` mean every check and cleanup step succeeded. If it reports
`state=failed`, keep the run directory and inspect the bounded end of
`run.log` plus the relevant component log before retrying.

The latest log path on this host is:

```text
/home/seorii/logs/maki-privileged-validation.latest/run.log
```

## Cleanup guarantees

The exit trap first asks an opener of the device that is still holding it
to close it (`stop-opener` in the run directory) and waits for it, then
attempts, in order, to unmount the test filesystem, deactivate
the uniquely named test VG, disconnect only the NBD connection created by the
run, terminate nbdkit normally with `SIGTERM`, remove the unique `/run/maki`
child directory, and delete only the `mktemp` work tree.
It also removes the per-volume `/run/maki-control` directory and the temporary
root-owned attach configuration created by the run.

Every raw attachment phase supplies a fresh backend identifier to
`maki-attach nbd-connect`.
The runner records it before connecting, so even a command that fails after
connecting can be cleaned up. Raw connect, disconnect, and LVM removal operations
hold the helper's `/run/maki-attach/attach.lock`; each removal requires the live
kernel backend to match the recorded identifier. A PID alone, a foreign backend,
or an unreadable identity never authorizes a disconnect or LVM removal. Failure
to prove ownership fails the run and preserves the daemon, backing, and remaining
cleanup artifacts for inspection. The shared attach lock is retained.

The `maki-attach` phase has its own identifier and trusted record. The exit trap
uses the helper's cleanup command for that phase, including a failed attach,
without holding the raw-operation lock. Only after helper cleanup succeeds may
the runner reconnect with a fresh raw identifier to remove disposable metadata.
This serializes cooperating helpers and runners; the dedicated NBD index must
still be reserved against unrelated administrative commands that bypass the lock.

If nbdkit does not exit after normal termination, the runner deliberately does
not escalate to `SIGKILL`; it fails and preserves the backing tree so an
operator can inspect the live process safely.

## Denial-check harness correction — 2026-11-16

Until this date the runner passed its unrelated-user socket check and its
unprivileged NBD disconnect check on any nonzero exit, without reading
`unrelated-user-socket.txt` or `unprivileged-nbd-ioctl.txt`. A sudo policy
refusal or an nbd-client usage error would also have passed, so in the results
below and in the privileged run of the
[R5 hardware validation](r5-hardware-validation-2026-10-03.md) those checks
show only that both commands failed. The runner now requires
`nbdinfo` to fail `connect` with `Permission denied`, and `nbd-client -d` to
report `Operation not permitted`, `Cannot open NBD: Permission denied` or the
netlink client's `Failed to disconnect device` while the run's own backend
stays connected. Any other output fails the run and is printed. No campaign
has been rerun with these checks.

## Helper-owned NBD connect — 2026-11-24

The helper now negotiates with the daemon's socket and connects and
disconnects NBD devices over netlink itself, so the runner neither requires nor
installs nbd-client. Its raw phases use `maki-attach nbd-connect` and
`nbd-disconnect` inside the attach lock, and the unprivileged disconnect check
runs the helper's own `nbd-disconnect` as the invoking user: it passes only when
the helper reports the kernel's `Operation not permitted` for
`NBD_CMD_DISCONNECT` while the run's backend stays connected, and the evidence
is kept as `unprivileged-nbd-disconnect.txt`. Every result below attached
through nbd-client, 3.27.1 (3.24 in the 2026-09-02 result); no campaign has
been run with the helper's own connect yet.

## Attach lifecycle and CI — 2026-11-26

The runner now detaches with an opener of the device and attaches again in
every run, `--kill-daemon` adds the cleanup after a killed nbdkit, a third
attach and a final detach, and CI's `kernel-lifecycle` job runs it with
`--kill-daemon` on GitHub's Ubuntu runner on every change. No result below
includes these checks, and none had been run on a host outside CI when this
was written.

## Disconnected recovery and the helper's inputs — 2026-11-27

`--kill-daemon` now kills nbdkit a second time and releases its device by
hand before cleanup, so that cleanup starts on a device that shows no
connection, and every run captures what the helper's readers parse after
the first attach. In both CI runs of 2026-11-26 the killed daemon's device
still showed its connection when cleanup started. Read from the kernel's
NBD driver, it keeps a connection's attributes until the last opener of the
device closes it, and a mounted filesystem or an LV mapping is such an
opener, so a device that shows no connection has no mount or mapping of it
left, and cleanup's disconnected recovery then has nothing to unmount or
deactivate and retires the record. The run logs what the device shows after
each step of the release by hand. CI's runs with these checks (2026-11-27,
GitHub's Ubuntu runner, at commits a6c2006, f933c7c, 8b9ef4d and 31b7ef8 of
#413; Linux `7.0.0-1020-azure`, and `7.0.0-1016-aws` at 8b9ef4d) passed
them. In the three whose logs are kept the device still showed the
connection after the disconnect with XFS mounted on the LV and after the
unmount, showed none once the LV's mapping was removed, and cleanup logged
disconnected recovery and left nothing. That shows the mapping keeping the
connection's attributes; the mount sits on the mapping, so its own effect is
not told apart. No run outside CI has these checks yet.

## Installed systemd combined Debian 12 GCE result — 2026-09-17

Revision `448c0b2a46bd748eb473e34405175db9b3cfa102` passed 12 combined
checks on a disposable `n2-standard-4` instance using
`debian-12-bookworm-v20260908`, Linux `6.1.0-53-cloud-amd64`, nbd-client
3.27.1, nbdkit 1.32.5, LVM 2.03.16, and XFS tools 6.1.0. The same revision's
[Linux and Windows CI run](https://github.com/seo-rii/maki/actions/runs/34713182759)
also passed.

The campaign installed the repository's release binaries, nbdkit plugin,
systemd templates, sysusers file, and tmpfiles file at their shipped paths. PID
1 resolved the qualified nbd-client, created the `maki` account, loaded a local
AES-GCM-SIV key through `LoadCredential=`, and started the packaged target,
daemon, attach, recovery, and per-start verification graph. The daemon ran as
`maki` with `NoNewPrivs=1`, no effective capabilities, and the packaged
sandbox. The workload used the pinned
`python:3.12-slim@sha256:78387bc3881b8273120a12ebe6c1ab22b018ccc2c9adf565ae1ac9b536e184ea`
image and default `rprivate` bind propagation.

The first container committed 16 SQLite WAL rows with `synchronous=FULL`. Two
successive `systemctl kill --kill-whom=main --signal=KILL` operations each
made the packaged recovery coordinator stop the old workload, clean the exact
single-PV/LV kernel attachment, start a new daemon, reattach and verify storage,
and create a distinct container. The independently fsynced root-owned ledger
reached 32 and then 48 rows. Daemon PIDs, workload invocation IDs, and container
IDs changed on both cycles; removed containers did not survive.

A root process then held the exact LV open while a third daemon received
`SIGKILL`. Both attach stop and recovery cleanup failed closed on the nonzero
mapping open count. The workload and old container stayed stopped, the ledger
remained at 48, and the NBD connection, mapping, backend identity, and trusted
volume record were retained. After the descriptor closed, an explicit recovery
retry cleaned and recreated the graph and a fourth container advanced the
ledger to 64. A fifth, independent one-shot container reported
`integrity_check=ok` and its database rows matched all 64 ledger entries and
payload hashes exactly.

The final path issued a successful drain after the deterministic workload had
closed its database, stopped the target, and waited for the workload, attach,
and daemon jobs to finish. The journal records workload stop before attach
cleanup and daemon stop, with no plugin unload drain error. Offline `maki check`
passed. No mount, mapping, NBD connection, holder, volume record, or test
container remained; the shared root-owned attach lock correctly remained.

Evidence and its manifest are under
`/home/seorii/logs/maki-systemd-combined-20260917`. The exact instance and its
auto-delete 50 GiB boot disk were deleted. Their lookups returned not found,
and fresh project-wide name queries returned zero `maki-*` instances and disks.

This qualifies one short local-provider, single-PV/LV, SQLite campaign using
installed repository artifacts. It did not exercise a distribution package
install or upgrade, remote providers, multi-LV/internal mappings, a foreign
device replacement, PostgreSQL, ClickHouse, MinIO, fresh-host restore, a
whole-VM cut during this database topology, long soak, or physical power loss.
Those limits keep the overall production decision at no-go.

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
[Testing and qualification](../testing.md).
