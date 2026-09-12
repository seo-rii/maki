# Firecracker guest crash validation — 2026-09-12

Twenty abrupt Firecracker guest terminations preserved every tested durable
write. All 20 cold restarts reached READY and verified the preceding generation
through authenticated native NBD reads. **This qualifies this guest-crash
scenario only; it does not certify production operation or physical power-loss
durability.** The L1 Linux host, its page cache and Google Cloud storage remained
running throughout.

Related: [qualification tiers](testing.md),
[native process and cgroup evidence](cgroup-fault-validation-2026-09-12.md),
[durable recovery contract](durable-recovery.md),
[production readiness review](production-readiness-review-2026-09-08.md).

## Environment and artifacts

| Layer | Executed configuration |
|---|---|
| L1 host | Google Compute Engine `asia-northeast3-a`, `n2-standard-4`, Intel Cascade Lake; Debian 12, Linux `6.1.0-53-cloud-amd64`; nested KVM enabled |
| VMM | [Firecracker v1.16.1](https://github.com/firecracker-microvm/firecracker/releases/tag/v1.16.1), x86_64 |
| L2 guest | Linux `6.18.44+`, 2 vCPUs, 512 MiB RAM; Debian userspace, native nbdkit `1.32.5`, libnbd through Python ctypes |
| Guest storage | Read-only ext4 root drive; separate writable 1 GiB ext4 data image as `/dev/vdb`, mounted at `/data`; virtio `cache_type=Writeback`, `io_engine=Sync` |
| Maki | Normal release CLI/native plugin, real `local-aes-gcm-siv`, disposable 32-byte key; 128 MiB logical volume with 16 MiB logical shard ranges |
| Runtime state | Fresh `/run` tmpfs each boot for NBD, control and readiness sockets; no guest network, kernel NBD attachment, LVM or XFS workload |

The guest kernel came from the
[official Firecracker CI artifact](https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/20260909-a8e1c3830545-0/x86_64/vmlinux-6.18.44).
The L1/L2 terminology follows Google's
[nested virtualization documentation](https://docs.cloud.google.com/compute/docs/instances/nested-virtualization/overview).
The Firecracker kernel and rootfs preparation requirements are described in
its [setup guide](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/docs/rootfs-and-kernel-setup.md).

Recorded SHA-256 values:

| Artifact | SHA-256 |
|---|---|
| Firecracker executable | `2fd0171309af7e24cf8dafc8a6f921c1434c49b5f9349bb996b7ed0a4deb8aa7` |
| Guest kernel | `d8ced68bd61e27b6813e2c993cc53a4029c59e13210672180591c84109684fe4` |
| `maki` CLI | `a483da59bc53ad05cae1393bc3274311e45ef20a574a8499f83d2dca6cf35f9f` |
| Native plugin | `25af501de315eecf3d6eb0572d4cd92edb547d50e916fb90da48b5dd7825bdbf` |
| Guest agent after PATH fix | `142cbc0cd72d83d61f2e03ba932bd6b98d0d4a98ff772a8e8fe13fc770035d19` |

The public checkout was `49021b906338358222a6e0ecc1ea5a22fb5c93d4`.
The CLI/plugin hashes match the normal release artifacts built from
`e894ae57fea294966bcb7ec84593732c55cbc220` for the earlier cgroup campaign;
its latest product change was `2a3f023`. The Firecracker harness and its PATH
correction were additional test code at execution time. These results are not
evidence of rebuilding every binary at the later documentation checkout.

## Fault and oracle protocol

The [host runner](../scripts/firecracker-powercut-validation.py) creates a new
Firecracker process for each boot, always opening the same data image. The
[guest PID 1 agent](../scripts/firecracker-guest-agent.py) mounts ext4 with
normal journal replay. Only boot 0 may initialize the Maki volume; later boots
refuse missing or changed volume/configuration. They never format, run repair
tools or silently create replacement data.

After nbdkit's startup recovery, provider checks and control bind send READY,
the guest connects through libnbd and requires FLUSH and native FUA capability.
Each write cycle changes sixteen 4 KiB units, two addresses in each of eight
logical shard ranges. Payloads differ by cycle and address. FLUSH cycles write
all sixteen units before a successful FLUSH; FUA cycles require every individual
FUA write to return successfully before emitting the batch ACK frame.

The serial protocol includes a run nonce, boot identity and command identity.
The host independently derives the expected payload hashes, validates the
complete ACK manifest, appends it to its own ledger and fsyncs the ledger and
parent directory. Only then does it SIGKILL the owned Firecracker process group
and reap the process. There is no preceding guest shutdown, Maki drain, unmount
or global sync. Firecracker's
[Writeback mode](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/vmm/src/devices/virtio/block/mod.rs)
advertises guest flushes; the
[Sync I/O engine](https://github.com/firecracker-microvm/firecracker/blob/v1.16.1/src/vmm/src/devices/virtio/block/virtio/io/sync_io.rs)
performs the host file sync when handling a flush. `Sync` describes the I/O
execution mode, not automatic durability of every ordinary write.

On the next boot, the host sends only the acknowledged offsets. The guest
reads through Maki/libnbd and returns the actual data hashes; the host compares
them with its retained oracle. Missing, duplicate or wrong readbacks fail the
campaign. The guest does not receive the expected hashes. No subsequent writes
begin until that generation has passed verification.

## Results and the failed first attempt

| Run | Write/crash cycles | Cold boots | FLUSH batches | FUA batches | Acknowledged 4 KiB write versions | Verified write versions |
|---|---:|---:|---:|---:|---:|---:|
| Successful smoke | 2 | 3 | 1 | 1 | 32 | 32 |
| Main campaign | 20 | 21 | 10 | 10 | 320 | 320 |

The main campaign made 20 durability cuts and one additional SIGKILL to clean
up the final verification-only boot. All 21 child return codes were `-9`.
Every boot reported the same data filesystem UUID,
`5c6229cf-585a-43bb-8801-aa122a1101d3`, and guest `write back` cache mode.
No owned Firecracker process remained after completion.

The 320 entries represent twenty generations of the **same sixteen addresses**,
not 320 distinct addresses or 320 FLUSH barriers. The ten FUA batches contain
160 individually acknowledged FUA writes. The ten FLUSH batches cover another
160 write versions. There were no acknowledged-data mismatches.

The first smoke attempt failed before READY because the minimal PID 1
environment's PATH did not include the directory containing `blkid`. The
runner reported failure instead of accepting the boot. A regression test was
added before setting an explicit system PATH for guest children; the corrected
smoke and main campaign then passed. This was a guest harness setup defect,
not a Maki durability failure. The
[harness tests](../scripts/test_firecracker_powercut_validation.py) also cover
false/incomplete ACKs, stale identities, malformed oracles, wrong readbacks,
failed barriers, actual child timeout cleanup and Python optimization.

An offline deep check after the main campaign passed. It reported required
durable proof sequence **320**, twenty journal segments and 320 records newer
than checkpoint sequence **0**, with the key canary present. The catalog and
allocated slot counts were zero. Thus these cuts exercised journal persistence
and recovery across eight logical address ranges; they do not demonstrate
checkpointed shard-slot durability or checkpoint reclamation under VM loss.

## Evidence and reproduction

The archived evidence is in the private local directory
`/home/seorii/logs/maki-firecracker-gcp-20260912-evidence/`.
The 80 files listed in `artifacts/manifest.sha256` passed SHA-256 verification.
They include `environment.txt`, image/binary hashes, each boot's Firecracker
configuration and serial/stderr captures, both campaigns' `results.json` and
host ACK ledgers, and `campaign-20/deep-check.log`. Instance and disk descriptions
were saved separately before deletion. Logs were inspected only after the
corresponding command or VM exited; live serial input was used as protocol
traffic, not as a success claim inferred from diagnostic text.

Completed launcher evidence:

| Check | PID | Exit | Private log under `/home/seorii/logs/` |
|---|---:|---:|---|
| First smoke, missing PATH | 1469771 | 1 | `maki-r3-firecracker-smoke-20260912T142311.284851Z.log` |
| Corrected smoke | 1479173 | 0 | `maki-r3-firecracker-smoke-retry-20260912T142443.180310Z.log` |
| Main 20-cycle campaign | 1483029 | 0 | `maki-r3-firecracker-campaign-20-20260912T142527.199086Z.log` |
| Offline deep check | 1500392 | 0 | `maki-r3-firecracker-deep-check-20260912T142815.375218Z.log` |

Reproduction needs an explicitly provisioned disposable Linux host with KVM,
the pinned Firecracker/kernel, Python 3 and a prepared rootfs. The rootfs needs
nbdkit, `libnbd.so.0`, Python 3, `mount`, `blkid`, the normal release CLI/plugin,
an executable agent at `/opt/maki/firecracker-guest-agent.py`, and a disposable
32-byte `/opt/maki/key`. Prepare `/proc`, `/sys`, `/dev`, `/run`, `/data` and the
initial console/null/ttyS0 device nodes before making the rootfs read-only.
Check binary/runtime compatibility. The separate data file must already be a
fresh ext4 filesystem; the runner deliberately does not format it.

Run the following inside a private background supervisor that records PID,
exit status and a log from launch. `--output` must name a new directory. Paths
below are placeholders for those reviewed disposable artifacts, not host disks.

```bash
python3 -B -m unittest discover -s scripts -p test_firecracker_powercut_validation.py -v
python3 -B scripts/firecracker-powercut-validation.py \
  --firecracker /absolute/path/firecracker \
  --kernel /absolute/path/vmlinux \
  --rootfs /absolute/path/rootfs.ext4 \
  --data /absolute/path/fresh-data.ext4 \
  --output /absolute/path/new-evidence-directory \
  --cycles 20 --memory-mib 512 --vcpus 2 --timeout 120
```

The guest uses the native plugin's startup readiness, not merely the presence
of a socket. Keep failed images and results for diagnosis. Confirm owned VMMs
have exited before opening an image elsewhere or repeating a run.

## Limits and cleanup status

The fault removes the L2 guest's RAM, kernel and dirty guest page cache. The
L1 kernel, host page cache and GCP Persistent Disk service survive. The fsynced
oracle is outside the killed guest but still inside L1. This is not an L1
crash, physical power cut, bare-metal device-cache test, WSL shutdown, or a
cloud control-plane forced stop of the workload VM. It does not exercise real
databases, an exported filesystem on kernel NBD/LVM/XFS, remote providers,
storage I/O failures, sustained load or arbitrary interruption points inside
an unacknowledged write. The cuts deliberately follow a complete ACK.

The runner reaps children on its ordinary error and timeout paths. SIGKILL of
the supervisor itself can bypass cleanup and leave a Firecracker child alive.
An operator must inspect that run's recorded PID/process identity and verify
termination before reusing or deleting its files; never use a global process
kill as cleanup.

**Cloud cleanup completed:** deletion of the disposable GCP instance and its
disk completed with exit 0 (PID 1510997, 105.83 seconds). Subsequent scoped
queries returned `instances=[]` and `disks=[]`; those responses are retained as
`instances-after-delete.json` and `disks-after-delete.json` in the evidence
directory. The deletion log is
`/home/seorii/logs/maki-r3-firecracker-gcp-delete-20260912T143017.929360Z.log`.
Local evidence remains retained independently of those deleted resources.
