# Performance and memory profiles

A performance result belongs to one revision, configuration and environment.
Record the intended deployment before comparing results. Maki has no universal throughput, latency or RAM
minimum. The scoped measurements in [status](status.md) are evidence for those
profiles only.

## Measure the engine

Build `cargo build --release --locked -p maki-benchmark`. Use a dedicated
benchmark configuration with an empty backing directory and the same provider,
crypto unit, request limits, cache and batching settings as the intended profile.
Use a test key with that provider; do not copy production credentials into a
report. This tool overwrites its working set, including filesystem metadata on
an existing volume. An existing volume requires the explicit `--destroy-data`
flag, even if it appears empty.

```sh
# 10,000 sequential 128 KiB writes, one final FLUSH, then verified reads.
maki-benchmark --json benchmark.toml 10000 131072 > benchmark.json

# Separate empty backing/configuration: each write includes FUA as well.
maki-benchmark --json --fua benchmark-fua.toml 10000 131072 > benchmark-fua.json
```

Positional defaults remain 10,000 operations and 4,096 bytes. Operations must
be positive; I/O size must be block-aligned and fit both the volume and
`nbd.maximum_io`. Invalid arguments are rejected before volume creation.
The working set wraps at the largest whole I/O slot in the device. Reads check
the benchmark pattern and its offset; a failed operation or mismatch exits
unsuccessfully without a success report.

Both text and JSON report throughput, IOPS and request latency. JSON schema
version 1 records provider type, operation count, I/O size, concurrency (one),
FUA selection, successful read verification, and the final FLUSH time.
The write throughput interval includes the final FLUSH; write latency samples
measure individual writes (including FUA when selected), and exclude that final
FLUSH. Read throughput includes verification; individual read latencies end
when the engine returns the buffer. Attach/self-tests, recovery, formatting
and report serialization are outside the timed I/O intervals.

`p50_upper_us`, `p95_upper_us` and `p99_upper_us` are nearest-rank histogram
upper bounds in microseconds, capped at the observed maximum. Each histogram
has a fixed 2,048-counter allocation independent of operation count. Its
nanosecond buckets have at most 3.125% relative width; this is a bounded-memory
estimate, not an exact sorted sample percentile. `mean_us` and `max_us` use
the actual observed durations.

This is a single-caller engine measurement. It does not run nbdkit, kernel NBD,
LVM, XFS, systemd hardening or a database. Immediate reads may hit the configured
plaintext cache and the backing's OS cache. Record cache mode and working-set
size; use separate cold-start and warm-cache profiles when that distinction
matters. Use the packaged stack and the selected DB's load tool for the
application's latency target. Do not compare debug-build numbers with release
numbers or buffered filesystem I/O with direct engine I/O.

## Compare remote mappings

Compare per-item HTTP with a batched HTTP mapping (`body.items_path` and matching
response indices), WebSocket or gRPC only when the provider implements the
required contract. Changing endpoint/mapping settings needs a stopped restart;
follow [credential and endpoint changes](key-rotation.md). Preserve encryption
key, compatibility identity, integrity and context-binding requirements.

Keep revision, data size, I/O size, caller count, cache state, endpoint count,
TLS proxy layout and network impairment identical between comparisons. Record
`crypto.batch`, `limits.max_active_callbacks`, provider concurrency limits,
retry policy, and actual latency/loss location. Do not increase all concurrency
limits at once: observe queueing, provider throttling and memory at each step.
With one item per HTTP request, the slowest item can dominate the parent
request even after R5-039's bounded parallelism.

The [2026-10-05 per-item HTTP experiment](qualification/debian13-postgresql-http-validation-2026-10-05.md#throughput-of-a-per-item-http-volume-r5-039)
measured 0.61 MiB/s with loopback delay of 10 ms ± 5 ms and 0.16–0.17 MiB/s
with 1% loss. That topology crossed the impaired loopback several times and
opened backend connections per request. These are neither WAN predictions nor
a performance target. Choose minimum throughput and maximum p95/p99 latency
for the actual application before tuning; keep all repetitions and failures,
not only the fastest sample.

## Establish a memory and capacity envelope

Measure the daemon and its cgroup separately. On the selected installed
instance, the following read-only commands identify both:

```sh
systemctl show maki@example.service -p MainPID -p ControlGroup -p MemoryCurrent -p MemoryPeak
maki status /etc/maki/volumes/example.toml
maki metrics /etc/maki/volumes/example.toml
```

For the reported PID, retain `/proc/<pid>/status` fields `VmRSS`, `VmHWM`,
`VmLck` and `VmSwap`. For its cgroup v2 path under `/sys/fs/cgroup`, retain
`memory.current`, `memory.peak`, `memory.events`, `memory.stat` and
`memory.swap.current`. A missing field is unavailable evidence, not zero.
Cgroup memory includes charged file cache and can exceed process RSS. Capture
before/after event-counter deltas within the same cgroup lifetime; service
restarts can reset the counters. Sample during startup/recovery, steady I/O,
checkpoint, provider stalls and return to idle, across the chosen fill ratios.

The memory envelope must cover request plaintext, serialized/decoded transport
copies, the plaintext cache, ciphertext overlay, allocation/catalog metadata,
runtime/connection state and recovery. `limits.max_plaintext_bytes`, cache size
and overlay bounds account for different subsets; adding them does not prove a
total-RSS upper bound. Keep both overlay bounds nonzero for a bounded profile.
See [transport memory](transport-memory.md) for owned-buffer protections and
library-private limitations. Check lock-failure diagnostics and the configured
memory-lock/secure-swap policy; `secure-buffers` is not proof that every
plaintext representation was locked.

Set the deployment memory ceiling and required headroom from measurements of
the worst selected profile. Record recovery time, peak RSS/cgroup memory, swap,
lock failures, OOM events and post-load retained memory. A low ceiling that was
merely touched without an OOM is not an established minimum. External
qualification remains required for that envelope.

Use `maki volume inspect` offline for geometry capacity estimates. Keep journal
and checkpoint reserves, filesystem overhead and DB temporary/WAL growth
outside the usable-data budget. Set the backing-space alert threshold above
the configured emergency reserve plus checkpoint headroom and measured
operational margin. Below write admission's threshold, XFS deletion and
`fstrim` may both fail: free unrelated space on the backing filesystem or
expand it through the existing operational procedure. Never delete Maki's
journal, proof, slot or witness files to recover space. See
[space reclamation](space-reclamation.md) and
[storage recovery](storage-recovery.md).
