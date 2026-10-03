# R5 hardware validation — 2026-10-03

This report records two campaigns run on disposable GCE VMs after the fifth
review's fixes ([remediation log](../review-remediation.md#fifth-review-2026-10-01-r5-001r5-034)).
It is a dated record of what these revisions did on these hosts; it does not
claim current state.

## Environment

| Item | Value |
|---|---|
| Project and zone | `hancomac`, `asia-northeast3-a` |
| Image and kernel | Debian 12.15, `6.1.0-53-cloud-amd64` (Debian 6.1.187-1) |
| Machine types | `e2-standard-2` (campaign A), `e2-standard-4` (campaign B), no service account or scopes, fixed termination time with `DELETE` |
| nbdkit | 1.32.5 (Debian) |
| nbd-client | 3.27.1 built from the `nbd-3.27.1` tag and installed under `/usr/local` (not a Debian package) |
| Rust (campaign B) | 1.99.0 stable via rustup |

## Campaign A: v3 discard whole-instance resets

- **Revision** `62f95ad`, release binaries built on the controller host:
  `maki` `fa5eea6e…6a68`, `libmaki_nbdkit.so` `1f1207ab…6ac3` (the hashes
  on the guest matched).
- **Harness** `scripts/gcp-reset-validation.py --profile v3-discard --cycles 10`,
  launched like the [2026-09-20 campaign](gce-discard-reset-validation-2026-09-20.md),
  with the local `local-aes-gcm-siv` provider. The external controller keeps
  its ACK ledger across resets.
- **Fault** ten whole-instance resets (RAM, kernel and page cache lost).
- **Oracle** per generation: sixteen 4 KiB writes, a trim of offset 0
  followed by a rewrite, a trim of offset 4096 left zero; FLUSH and FUA
  generations alternate. After each reset the guest's readback must match
  the controller's independently derived final state.
- **Result: passed.** 11 distinct boot IDs, 10 complete ACK generations, every
  acknowledged unit read back (the rewritten block and the persistent zero
  block included). Offline deep check: required durable proof and checkpoint
  sequence 190, 8 shards, 15 allocated slots, 0 invalid, verdict `clean`.
  These match the 2026-09-20 campaign, now with the R5 discard changes
  (punch after the checkpoint state is durable, long trims, tombstone
  admission, header-only already-zero checks).
- **Cleanup** instance and both disks deleted; exact-name listings empty.

Revisions after `62f95ad` that campaign B ran (`f78cc70`, `96fa032`,
`adcebfe`) change only the privileged helper's command `PATH`, the
validation script and documentation, not the data path campaign A exercised.

## Campaign B: privileged validation and packaged lifecycle

Revision `adcebfe` (attempt 6; five earlier attempts are listed below).

### Privileged validation

`scripts/privileged-linux-validation.sh --discard --device /dev/nbd15`:
**25 of 25 checks passed.** Beyond the established checks (kernel NBD,
single-PV LVM/XFS, pinned attach, verify, fio with CRC32C, SQLite WAL with
`synchronous=FULL` and `integrity_check`, idempotent cleanup, offline check)
this run added:

- the XFS mount carries `nosuid,nodev`
  (`rw,nosuid,nodev,noatime,attr2,inode64,…`);
- `maki-attach attach` refuses an attach config owned by the invoking user
  with a "root-owned" error before touching state;
- on a v3 `--discard` volume, a 64 MiB file was deleted and `fstrim` ran
  through XFS, LVM and kernel NBD (`discard_max_bytes` 2,199,023,255,040);
  after a device flush and a checkpoint the backing's allocated bytes fell
  from 159,571,968 to 80,592,896. In attempt 5 the journal's appended
  sequence rose by 17,093 tombstones for the trim.

### Packaged quick start

The Debian package built from the same revision (`maki.deb` `7f7db2a8…72c1`)
was installed with `dpkg --force-depends` (the source-built nbd-client is not
a registered package), then [`quickstart.md`](../getting-started/quickstart.md)
was followed with assertions on a 2 GiB v3 volume: **11 of 11 checks passed.**

- `maki@demo` ran as `maki` with the R5-031 sandbox in effect
  (`DevicePolicy=closed`, `ProtectClock`, `ProtectKernelLogs`,
  `ProtectHostname`, `RestrictRealtime`, `RestrictNamespaces`,
  `SystemCallArchitectures=native`,
  `RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_UNIX`, empty
  capability bounding set, `NoNewPrivileges`); its journal showed no denial.
- `maki-workload@demo.target` attached through `maki-attach@` onto the
  root-owned `/srv/demo` (mode 0700), mounted `nosuid,nodev`, wrote the
  sentinel; `maki-attach verify` passed; `maki status` reported ready.
- `fstrim` trimmed 1.4 GiB through the packaged lifecycle.
- `maki drain`, a planned stop, and `maki check --deep`: 16,466 allocated
  slots, 0 invalid, verdict `clean`.
- After a restart the verify gate passed and the written file read back
  unchanged.

### Earlier attempts

Each ran on its own VM, which was deleted with empty listings.

| Attempt | Revision | Stopped at | Cause and fix |
|---|---|---|---|
| 1 | `62f95ad` | setup | Campaign driver: `nbd-client -h` exits non-zero under `pipefail` |
| 2 | `62f95ad` | privileged | Campaign driver passed an unsupported `--run-dir` |
| 3 | `62f95ad` | first `maki-attach` step | **Product regression.** R5-023's fixed `PATH` omitted `/usr/local/sbin`, where the source-built nbd-client lives; fixed in `f78cc70` (systemd's default service `PATH`) |
| 4 | `f78cc70` | privileged discard check | **Script bug.** `blockdev --flushbufs` sends no cache flush, so the trims stayed volatile; fixed in `96fa032` (`sync /dev/nbd15`) |
| 5 | `96fa032` | packaged bootstrap | **Documentation bug.** The quick start passed `/dev/nbd0` to nbd-client 3.27, which takes the kernel name over netlink; fixed in `adcebfe`. The privileged run passed 25/25 |

## Not covered

- Power loss on physical hardware, hypervisor-level power cuts, and long
  soak runs.
- A database workload on a v3 discard volume, and `fstrim` under space
  pressure near the emergency reserve.
- The rollback-protected backing, remote providers, and multi-volume hosts.
- `SystemCallFilter` and `MemoryDenyWriteExecute`, which the unit does not
  set.
- nbd-client installed as a Debian package rather than under `/usr/local`.
