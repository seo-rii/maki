# Constrained recovery cgroup and RSS validation — 2026-09-19

## Result

Four independent Docker campaigns recovered after workload OOM at the requested
memory cap: two at 48 MiB and two at 64 MiB. Every constrained recovery reached
READY, authenticated all 136 externally acknowledged units, recorded no
recovery OOM, and was followed by a successful 192 MiB readback and offline
deep check with zero invalid slots.

The largest observed nbdkit process `VmHWM` was 11,415,552 bytes. The 48 MiB
cgroup reached its exact limit in both runs and recorded memory-max events. The
64 MiB cgroup recorded no max events; its larger peak was 60,952,576 bytes.
For this fixed profile, the measurement does not establish a universal RSS bound
or a minimum for another volume
geometry, provider, cache, fill ratio, kernel, workload, or deployment topology.

## Environment and immutable inputs

- Linux `6.1.0-53-cloud-amd64`, Docker 29.1.2, cgroup v2, swap disabled for
  every target container.
- Bounded-replay image
  `sha256:fdb24012f01fcc78348c8dfe03ae2f07050ba3e37e4f1f2745f49d4d3074faf8`,
  built from product revision `733833c`.
- Metrics and parameterized-cap harness revision `84492a0`; harness SHA-256
  `46468ac875d5de7fd7738e4bc1168d0f4a618c9be21d5f7aef89b1004789f756`.
- Local AES-GCM-SIV provider, 128 MiB virtual volume, 4 KiB units, 16 MiB
  shards and journal segments, four nbdkit threads, and no network.
- Private evidence is retained under
  `/home/seorii/logs/maki-rss-bound-20260919-*`. The detached supervisor exited
  zero, and its final owned-container inventory was empty.

## Observations

All byte figures below are read after READY and authenticated readback. `VmHWM`
and `VmRSS` come from the nbdkit PID 1 `/proc` status. Cgroup peak includes
charged page cache and kernel memory that process RSS does not.

| Recovery cap | Run | Uncheckpointed pressure writes before OOM | cgroup current (bytes) | cgroup peak (bytes) | `memory.events:max` | nbdkit `VmHWM` (bytes) | nbdkit `VmRSS` (bytes) |
|---:|---:|---:|---:|---:|---:|---:|---:|
| 48 MiB | 1 | 21.75 MiB | 22,319,104 | 50,331,648 | 62 | 11,415,552 | 11,112,448 |
| 48 MiB | 2 | 19.75 MiB | 24,576,000 | 50,331,648 | 38 | 11,354,112 | 10,989,568 |
| 64 MiB | 1 | 21.75 MiB | 31,907,840 | 60,952,576 | 0 | 11,337,728 | 11,018,240 |
| 64 MiB | 2 | 21.75 MiB | 31,916,032 | 60,657,664 | 0 | 11,313,152 | 10,969,088 |

The pressure phase in every run first lowered the running target to 32 MiB and
continued distinct, unbarriered 256 KiB writes until Docker reported
`OOMKilled=true`, exit 137. The host ledger contained only earlier FLUSH/FUA
successes. A new container then recovered the same backing at the table's cap.
Each constrained recovery returned `verified_units=136` with zero `oom` and
zero `oom_kill` events. A separate 192 MiB recovery repeated the authenticated
readback, and the offline deep checker found no journal record newer than the
checkpoint and zero invalid slots.

## Boundary of the result

The four observed process high-water marks put this profile's nbdkit RSS at or
below 11,415,552 bytes during recovery. They do not bound library or kernel
memory in other processes, and they are not a proof that future code cannot
allocate more. The cgroup result is the stronger deployment observation: 64 MiB left
6,156,288 bytes between its larger measured peak and its hard cap without a
single max event, while 48 MiB had no such margin despite completing safely.

The test does not cover a maximum catalog, maximum virtual volume, remote
provider buffers, large cache configuration, multiple concurrent volumes,
filesystem or database processes in the same cgroup, long-duration load, or a
production fill ratio. Those profiles still require their own memory target
and repeated worst-case recovery measurements.
