# GCE discard/reset validation — 2026-09-20

This document defines the opt-in `v3-discard` GCE hard-reset campaign. The
campaign has not yet been run. Results, artifact hashes, resource identities,
and cleanup evidence must be added only after the disposable resources have
been exercised and deleted. The existing default `v2` write/readback campaign
remains unchanged.

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

