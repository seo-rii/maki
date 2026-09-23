# GCE discard/reset validation — 2026-09-20

This document records the completed opt-in `v3-discard` GCE hard-reset campaign.
The unattended campaign passed on 2026-09-20 and its disposable resources were
deleted. The existing default `v2` write/readback campaign remains unchanged.

## Qualification target

Run ten whole-instance resets against the normal release CLI and native nbdkit
plugin with the real `local-aes-gcm-siv` provider. The controller must run
outside the disposable VM and retain its private ACK ledger across resets. Use
the same resource-identity, boot-identity, shutdown-witness, SSH-liveness, and
offline deep-check gates described in
[the v2 campaign](gce-reset-validation-2026-09-13.md).

The guest requires libnbd to report native FLUSH, FUA, and TRIM support before
the controller accepts READY. Even generations use explicit FLUSH barriers;
odd generations use FUA on every write, trim, and rewrite command.

## Discard oracle

Each generation first writes the same sixteen independently derived 4 KiB
blocks used by v2. It then trims two different blocks:

- offset 0 is trimmed and subsequently rewritten with a distinct,
  generation-specific 4 KiB payload;
- offset 4096 is trimmed and left untouched, so the next boot must read a full
  zero block there.

In FLUSH generations, the guest flushes after the initial writes, after both
TRIM commands, and after the rewrite. In FUA generations, every operation
carries `LIBNBD_CMD_FLAG_FUA`. The guest emits an ACK only after all applicable
barriers succeed.

The external controller derives the initial writes, trim ranges, rewrite hash,
and final sixteen-block state without accepting expected values from the
guest. It validates and fsyncs that complete manifest before resetting the VM.
After reboot it compares the guest's raw readback hashes with the final oracle:
the rewrite must survive at offset 0 and the zero block must survive at offset
4096. This distinguishes successful trim-followed-by-rewrite behavior from
durable discard itself.

## Invocation

Use a new private output directory and the explicit profile flag:

```bash
python3 -B scripts/gcp-reset-validation.py \
  --profile v3-discard \
  --project PROJECT \
  --zone ZONE \
  --instance DISPOSABLE_INSTANCE \
  --data-disk DISPOSABLE_DATA_DISK \
  --cycles 10 \
  --timeout 180 \
  --output /absolute/path/to/new-private-evidence
```

Before execution, record the release binary hashes and immutable GCE resource
identities. After the final readback and offline deep check, preserve bounded
controller evidence, delete the disposable instance and all attached disks,
and record scoped empty instance/disk queries. Do not present this document as
qualification evidence until those results and cleanup checks are recorded.

## Local harness verification

The harness is developed test first. Run both normal and optimized Python
modes before starting the cloud campaign:

```bash
python3 -B -m unittest scripts.test_gcp_reset_validation -v
PYTHONOPTIMIZE=1 python3 -B -m unittest scripts.test_gcp_reset_validation -v
```

Both normal and optimized Python passed all 66 fault-oracle regressions before
launch. The combined product snapshot passed 1,057 Rust tests, strict dependency
audit, formatting, and workspace all-target Clippy.

## Completed campaign

The fixed product revision is `fe259e3` and harness revision is `f5bde3e`.
The normal release build completed with exit 0 under
`~/logs/maki-v3-release-20260920T111425Z/`.
The independent controller used PID 1485278 and its private run directory is
`~/logs/maki-gce-v3-20260920T1118Z/`.

The launcher selects one Debian 12 `e2-standard-2` VM with a 20 GiB boot disk
and separate 20 GiB ext4 data disk in project `hancomac`, zone
`asia-northeast3-a`. Its generated names are `maki-v3-reset-b03ff94591` and
`maki-v3-reset-b03ff94591-data`. No service account or scopes are attached.
Both disks are auto-delete. In addition to the launcher's final cleanup, a
fixed two-hour termination time requests instance deletion even if the
controller is interrupted. See the official
[VM runtime limit](https://docs.cloud.google.com/compute/docs/instances/limit-vm-runtime).

The launcher saved phase progress in `status.json`, terminal exit code in
`exit.status`, and private command logs beside `supervisor.log`. It collects
setup diagnostics and volume metadata before deletion, then verifies exact
empty instance and disk queries. A campaign pass is only reported if the
controller's ACK/readback/deep-check result passes and cleanup is confirmed.
This run reported `passed` with exit 0 at 2026-09-20 11:27:29 UTC. Ten resets
produced eleven distinct boot IDs and all 160 acknowledged units were verified.
The final offline deep check found required proof and checkpoint sequence 190,
eight shards, 15 allocated slots, and zero invalid slots. The preserved external
ACK ledger contains ten complete generation records. Cleanup completed with
empty exact-name instance and disk queries; a later scoped `gcloud` recheck also
found neither generated name.
The 160 checks are ten generations of the same sixteen addresses, including
the persistent zero block and the rewritten block, rather than 160 distinct
addresses. The 190 journal operations comprise 170 writes and 20 trims.

```bash
cat ~/logs/maki-gce-v3-20260920T1118Z/status.json
test ! -f ~/logs/maki-gce-v3-20260920T1118Z/exit.status || cat ~/logs/maki-gce-v3-20260920T1118Z/exit.status
```

The volume was 128 MiB, used eight 16 MiB logical ranges and the real local
AES-GCM-SIV provider. This is a native userspace NBD reset test; it does not
mount a production database or power-cycle the physical Persistent Disk service.
