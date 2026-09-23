# GCE whole-instance reset validation — 2026-09-13

Ten hard resets of a disposable Google Compute Engine instance preserved every
tested durable write. All ten reset operations completed successfully, killed
the existing SSH session, and produced a new Linux boot identity. Each new boot
authenticated and read back the preceding generation through the native Maki
nbdkit plugin. **This qualifies the tested GCE reset path only. It does not
certify production operation or physical power-loss durability.**

This campaign removes the workload VM's RAM, kernel, and page cache. It is
therefore stronger cloud-VM reset evidence than the earlier
[Firecracker guest campaign](firecracker-validation-2026-09-12.md), whose L1
host stayed alive. Google documents `instances reset` as an immediate hard
reset that does not perform a clean guest shutdown, wipes instance memory, and
leaves attached disks unchanged. See the
[gcloud reset reference](https://docs.cloud.google.com/sdk/gcloud/reference/compute/instances/reset)
and [Compute Engine reset guide](https://docs.cloud.google.com/compute/docs/instances/reset-instance).

Related: [qualification tiers](testing.md),
[native process and cgroup evidence](cgroup-fault-validation-2026-09-12.md),
[durable recovery contract](durable-recovery.md), and
[production readiness review](production-readiness-review-2026-09-08.md).

## Environment

| Component | Executed configuration |
|---|---|
| Workload VM | Disposable standard-provisioned GCE `n2-standard-4` in `asia-northeast3-a`; Debian 12, Linux `6.1.0-53-cloud-amd64`; no service account attached |
| Boot disk | Separate 30 GiB balanced Persistent Disk, deleted with the instance |
| Data disk | Separate 20 GiB balanced Persistent Disk, attached as `maki-data`; ext4 mounted at `/mnt/maki-data` through `/dev/disk/by-id/google-maki-data` |
| Maki | Normal release CLI/native plugin, real `local-aes-gcm-siv`, disposable 32-byte key; 128 MiB logical volume and eight 16 MiB logical ranges |
| Client | libnbd through Python `ctypes`; native FLUSH and FUA both required before READY |
| Reset controller | Independent host process invoking `gcloud compute instances reset`; private ACK ledger fsynced on the controller before each reset |

The CLI SHA-256 was
`a483da59bc53ad05cae1393bc3274311e45ef20a574a8499f83d2dca6cf35f9f` and the
native plugin SHA-256 was
`25af501de315eecf3d6eb0572d4cd92edb547d50e916fb90da48b5dd7825bdbf`.
These are the normal release artifacts built from `e894ae5` for the preceding
cgroup campaign. The latest product-code change was `2a3f023`; later changes
through the execution checkout `2f4f107` were tests and documentation. The
host and guest GCE harness was uncommitted qualification code during execution
and was subsequently committed without content changes as `326917b`.

Stable resource identities recorded before and throughout the campaign were:

| Identity | Value |
|---|---|
| Instance ID | `3597397282242746751` |
| Data disk ID | `5953009487719225751` |
| Data attachment | device name `maki-data` and the same full disk resource URL on every boot |
| Data filesystem UUID | `3d58c270-3c59-4adb-b621-89b9bf926f13` |

## Fault and oracle protocol

The [external controller](../scripts/gcp-reset-validation.py) first freezes the
instance ID, data disk ID and self-link, attachment URL and device name, and
filesystem UUID. The [guest agent](../scripts/gcp-reset-guest.py) starts the
real nbdkit plugin and waits for its startup READY notification. It then opens
the Unix NBD endpoint with libnbd and refuses to proceed unless FLUSH and FUA
are both available.

Each generation changes sixteen 4 KiB units: two offsets in each of eight
16 MiB logical ranges. Even generations issue all writes and then one FLUSH.
Odd generations put FUA on each individual write. The guest emits an ACK only
after the complete barrier succeeds. The controller independently derives the
payload hashes, validates the complete ordered manifest, appends it to a local
ledger, and fsyncs both the ledger and its parent directory.

Immediately after that durable host ACK, the controller runs:

```bash
gcloud compute instances reset INSTANCE \
  --project PROJECT --zone ZONE --quiet --format=json
```

It sends no guest sync, unmount, drain, shutdown, reboot, or stop request after
the ACK. A systemd witness service stays active on every boot and appends a
record from `ExecStop`. The controller requires that record to remain absent,
so a clean systemd shutdown cannot be misclassified as a hard reset. It also
requires the reset command to exit zero, the old SSH child to have been alive
immediately before reset and to terminate afterward, and the same GCE resources
to return in `RUNNING` state.

On each next boot the guest reads the previous generation before starting any
new write. It reports actual hashes without receiving expected hashes. The
controller rejects a missing, reordered, duplicated, or mismatched readback.
Every boot ID must be globally unique across the run. A final read-only boot
verifies generation nine, exits cleanly, and permits a host-invoked offline
deep check.

## Results

The two-cycle smoke used the initial volume and passed one FLUSH and one FUA
generation. The data disk was then reformatted, remounted, and initialized as a
fresh Maki volume before the main campaign.

| Run | Hard resets | Observed boots | FLUSH generations | FUA generations | Acknowledged 4 KiB write versions | Verified write versions |
|---|---:|---:|---:|---:|---:|---:|
| Smoke | 2 | 3 | 1 | 1 | 32 | 32 |
| Main campaign | 10 | 11 | 5 | 5 | 160 | 160 |

All ten main reset commands returned zero. All ten pre-reset SSH children
terminated with status 255, and all post-reset instance observations were
`RUNNING`. The main results contain eleven distinct boot IDs, one stable
filesystem UUID, and one stable set of GCE resource identities. Every READY
record reported the shutdown witness active and its graceful-stop ledger
absent. No nbdkit process remained after the final verification-only boot.

The 160 entries are ten versions of the same sixteen logical addresses, rather
than 160 distinct addresses. Five FLUSH barriers cover 80 versions; the five
FUA generations contain 80 individually acknowledged FUA writes.

The final offline deep check passed with required durable proof sequence 160,
checkpoint sequence 160, eight shards, sixteen allocated slots, and zero
invalid slots. The journal had no records newer than the checkpoint. This run
therefore exercised recovery plus checkpoint advancement; it did not leave the
entire campaign solely in an unreclaimed journal tail.

Cloud Audit Logs contain twelve distinct completed
`v1.compute.instances.reset` operations: two for the smoke and ten for the main
campaign. Each operation has one first and one last audit entry. This agrees
with the controller results and the twelve observed boot transitions.

## Evidence and reproduction

Private evidence is retained under
`/home/seorii/logs/maki-gcp-reset-20260913-evidence/`. Its 43-file
`artifacts.manifest.sha256` passed `sha256sum --check`. The directory includes
resource descriptions before and after the campaign, the reset audit entries,
guest environment and binary hashes, every boot's bounded stdout/stderr, both
host ACK ledgers, final results, and post-deletion empty resource lists.

The harness was developed test first. Missing behavior, the required shutdown
witness, transient post-reset SSH retry, and the pre-reset live-SSH guard each
failed a focused regression before implementation. The final focused suite
passed 26 tests in normal mode and 26 with `PYTHONOPTIMIZE=1`; the combined
cgroup, Firecracker, and GCE oracle suite passed 51 tests locally. The retained
RED logs are `maki-gcp-reset-tdd-red-20260912.log`,
`maki-gcp-reset-witness-red-20260913.log`,
`maki-gcp-reset-ssh-retry-red-20260913.log`, and
`maki-gcp-reset-precut-ssh-red-20260913.log` under `/home/seorii/logs/`.
[Commit `326917b` CI](https://github.com/seo-rii/maki/actions/runs/34701738540)
passed the Ubuntu and Windows jobs. Ubuntu ran the combined fault-oracle suite
after installing the native NBD tools; Windows passed formatting, strict Clippy,
and the workspace suite while correctly skipping Linux-only oracle execution.

Completed launcher evidence:

| Operation | Exit | Duration | Private log under `/home/seorii/logs/` |
|---|---:|---:|---|
| Two-reset smoke | 0 | 57.09 s | `maki-r3-gcp-reset-smoke-20260912T150436.974652Z.log` |
| Fresh-volume baseline | 0 | 3.10 s | `maki-r3-gcp-reset-rebaseline-20260912T150650.219312Z.log` |
| Ten-reset main campaign | 0 | 234.32 s | `maki-r3-gcp-reset-main-20260912T150720.148977Z.log` |
| Instance and all attached-disk deletion | 0 | 106.51 s | `maki-r3-gcp-reset-delete-20260912T151330.777239Z.log` |

Launcher filenames use UTC timestamps; the report date uses Asia/Seoul time.

The harness has no third-party Python dependencies. Prepare an explicitly
authorized disposable GCE instance with a separate persistent data disk, mount
that disk at `/mnt/maki-data`, install the pinned Maki binaries and guest agent,
and create the configuration, key, volume, and shutdown witness. Run the
controller outside the workload VM. `--output` must name a new private
directory.

```bash
python3 -B -m unittest discover -s scripts \
  -p 'test_*validation.py' -v

python3 -B scripts/gcp-reset-validation.py \
  --project PROJECT \
  --zone ZONE \
  --instance DISPOSABLE_INSTANCE \
  --data-disk DISPOSABLE_DATA_DISK \
  --cycles 10 \
  --timeout 180 \
  --output /absolute/path/to/new-private-evidence
```

Delete the instance with all attached disks after collecting evidence, then
use scoped instance and disk list queries to verify that no named resources
remain.

## Limits and cleanup status

GCE reset removes the workload VM's RAM, kernel, and kernel page cache, while
the Persistent Disk service and its physical storage path remain operational.
This is not a physical power cut, storage-controller cache-loss test, or
bare-metal qualification. The campaign used userspace libnbd over a Unix socket
and did not attach kernel NBD, LVM, or XFS. It did not run a real database,
remote crypto provider, provider outage, sustained load, or interruption at
arbitrary points before an ACK. Ten resets are useful target evidence but do
not meet the separate 300-cut QEMU goal or a long-duration workload goal.

**Cloud cleanup completed.** Deleting the disposable instance with all attached
disks completed successfully. Subsequent project-scoped queries found zero
matching instances and zero matching boot or data disks. The empty JSON results
are included in the evidence manifest; the private evidence remains local.
