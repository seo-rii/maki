# Privileged Linux Validation

This runbook closes the safe, host-dependent part of Maki's Linux data-path
qualification. It drives a disposable Maki export through kernel NBD, LVM,
XFS, fio, and SQLite, while keeping the chosen device and all artifacts easy
to audit.

The runner is intentionally conservative: it accepts only `/dev/nbdN`,
requires the same path again as an explicit wipe confirmation, and stops if
the device is already connected, mounted, or held by another block device. It
does not unload kernel modules and never targets a physical disk.

## Scope

The automated run checks:

- release builds and the nbdkit `plugin_init` export;
- nbdkit/libnbd negotiation and duplicate-attach exclusion;
- the nbdkit process's unprivileged UID and empty effective capability set;
- denial of the protected socket to an unrelated user;
- kernel `/dev/nbdN` attachment and exported geometry;
- denial of an NBD disconnect ioctl to the invoking unprivileged user;
- raw-device fio with CRC32C verification and periodic `fsync`;
- disposable LVM and XFS creation;
- the real `maki-attach` attach and detach paths;
- unprivileged fio through the mounted XFS filesystem; and
- a SQLite WAL checkpoint with `synchronous=FULL` and `integrity_check`.

The run does **not** force a daemon crash, send `SIGKILL`/`SIGSEGV`, induce an
OOM, interrupt power, test a real disk, or modify installed Maki systemd
units. Those scenarios need an isolated destructive-test host and are outside
this safe runner.

## Run

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

If nbdkit does not exit after normal termination, the runner deliberately does
not escalate to `SIGKILL`; it fails and preserves the backing tree so an
operator can inspect the live process safely.

## Relationship to other qualification tiers

This run supplies privileged kernel-NBD, filesystem, and safe host privilege
evidence. It is not evidence for destructive database crash campaigns,
hard-power-loss testing, or long-duration mixed-workload qualification; those
remain separate, isolated-host gates.
