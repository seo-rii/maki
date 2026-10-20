# Concurrent engine benchmarks

`maki-benchmark` performs verified I/O through the configured provider and
real engine on a disposable volume. A new volume is initialized automatically;
an existing volume requires `--destroy-data` because the benchmark overwrites
its working set. Configuration and workload bounds are checked before creation.
An existing volume must retain its stored geometry.
This also applies to local and remote rollback-protected volumes: reuse opens
the existing witness-backed format rather than starting enrollment again.
Incomplete or invalid formats are rejected even with `--destroy-data`.

The default remains one caller, sequential writes, one final FLUSH, then
verified sequential reads, followed by a separate final verification sweep.
`ops` is the count in each phase; the JSON report
keeps `schema_version = 1` and the existing `write`, `read`, `flush_us`,
`concurrency`, `fua`, and `read_verified` fields.

`read_verified` is true only when at least one measured read passed its data
comparison. The additive `verified_read_operations` field counts those reads,
and `read_verification` is `"passed"` or `"skipped"`. A zero-read mixed run,
including `--read-percent 0` or a short run rounded down to zero reads, reports
`false`, `0`, and `"skipped"`; text output says `skipped: no read operations`.
Read or comparison failures exit unsuccessfully without a success report.
Working-set setup writes and attach self-tests are not measured read verification.
The final sweep has its own `verification` section and never changes the
measured-read verdict or sample count, including for `--read-percent 0`.

```sh
maki-benchmark --json /path/to/disposable-volume.toml 10000 4096
maki-benchmark --json --concurrency 32 --access random --read-percent 70 \
  --working-set 64MiB --flush-every 1000 --seed 12 \
  /path/to/disposable-volume.toml 100000 4096
```

| Option | Behavior |
| --- | --- |
| `--concurrency N` | At most N submitted I/O jobs and their completion results; 1–256, default 1. Compare 1, 2, 8 and 32 with the same configuration. |
| `--access sequential|random` | Sequential wrapped addresses or reproducible independent random addresses; default sequential. |
| `--seed N` | Nonnegative seed for random addresses; default 1. |
| `--read-percent N` | Mixed workload with N percent reads, 0–100. `ops` becomes the total measured read/write count; reads number `floor(ops × N / 100)`. Omit to retain two phases. |
| `--working-set SIZE` | Positive multiple of I/O size within the volume, accepting bytes or KiB/MiB/GiB suffixes. Default is `min(ops, volume I/O slots) × io-size`. |
| `--fua` | Every measured write requests FUA. |
| `--flush-every N` | Drain each cohort of N measured operations, then FLUSH; requires N > 0. Phased reads do not issue FLUSH. The last cohort always has a final FLUSH. |

I/O size must fit the device and configured maximum request size and be a
multiple of its device block size. `ops` must be in 1–1,000,000,000. Unknown,
duplicate, missing, malformed and out-of-range workload arguments fail before
backing creation.

Mixed workloads initialize the complete working set and FLUSH it before
measurement; `setup.writes`, `setup.flushes` and `setup.elapsed_seconds` report
that cost separately. Each address starts at generation zero; every successful
measured write advances its generation and repeats the address and generation
throughout the payload. Reads compare against the latest successful write, so
returning an earlier value at the correct address fails verification.
Reads and writes sharing an address execute in submission order. A busy address
delays submission until its preceding operation finishes, so hot addresses can
reduce effective concurrency. Unrelated addresses use independent locks.
Phased random reads repeat the written address sequence, including wraps and
repeated draws. Choose a working set larger than the configured cache to measure
storage/provider behavior beyond cache capacity.

After all measured operations and resource sampling finish, a final sweep
compares the latest expected generation at every initialized address. Mixed
mode checks the entire working set, including addresses that received only a
setup write. Phased mode checks every distinct address written during the write
phase and skips unwritten addresses in a larger working set. A read failure or
data mismatch in this sweep exits unsuccessfully without a success report.
The check includes each slot's last measured write even when no measured read
follows it. Sequential mixed schedules can assign disjoint addresses to reads
and writes; successful measured reads alone do not validate those writes.

The sweep uses live reads through the same engine and cache. It does not close
and reopen the volume, bypass the cache, or qualify persistence after a crash or
power loss. Those guarantees require separate recovery and durability campaigns.

The oracle stores eight bytes per I/O slot, capped at 64 MiB (8,388,608 slots,
or a 32 GiB working set for 4 KiB I/O). Larger working sets are rejected before
backing creation. Only addresses with an outstanding job/result retain a lock,
so lock metadata is bounded by concurrency (at most 256 entries).

Jobs finish and refill in completion order while request memory remains bounded
by concurrency and I/O size. Periodic FLUSH drains a cohort before its barrier; if
the cohort is smaller than concurrency it also limits effective parallelism.

## Reading the report

Each `write`, `read` and new `flush` section includes `latency.samples`, mean,
p50, p95, p99 and maximum, with a fixed-size histogram whose quantile upper
bounds overestimate by at most 3.125%. Read/write latency measures the engine
call; payload generation and read verification remain part of throughput time.
Default write throughput includes its final FLUSH, as before. Mixed read/write
throughput divides each operation count by the complete measured workload time,
including barriers. Empty read/write classes have zero counts and finite zero
latencies/throughput. `flush_us` is the last measured barrier latency; the
`flush` histogram covers all measured barriers and excludes setup.

`workload` records access, phase/mixed mode, read ratio, working-set bytes,
barrier spacing and seed. The additive `verification` section reports distinct
slot coverage separately from the measured operation counts:

| Field | Meaning |
| --- | --- |
| `written_slots` | Distinct slots with a successful measured write; setup writes are excluded. |
| `read_after_write_verified_slots` | Distinct slots for which a measured read successfully compared a nonzero measured-write generation. A later write may have advanced the slot again. |
| `final_sweep_verified_slots` | Slots whose latest expected generation passed the final sweep; all working-set slots in mixed mode, only written slots in phased mode. |
| `final_sweep_elapsed_seconds` | Time spent in the separate final sweep, excluded from measured throughput, latency and resource sampling. |

A 50% sequential mixed run over an even number of slots can therefore report
successful measured reads with `read_after_write_verified_slots = 0`; its final
sweep still checks all latest writes. A 100% read run has `written_slots = 0`
and sweeps the complete initialized working set.

`resources` distinguishes exact and sampled values:

- `peak_pending_operations` counts submitted, unfinished engine calls and
  returns to `pending_operations_at_exit = 0` on success.
- `oracle_generation_bytes` reports eight bytes per tracked slot, excluding
  allocator overhead and the at-most-256 sequencing locks.
- `observed_peak_active_callbacks`, `observed_peak_plaintext_bytes`,
  `observed_peak_overlay_bytes` and `observed_peak_journal_pending_bytes` come
  from nonblocking engine snapshots sampled every 1ms. Short peaks can fall
  between samples; snapshots can use the latest observation while the volume
  lock is busy. `monitor_samples` and `monitor_interval_ms` describe that
  sampling cost.
- `process_peak_rss_bytes` reads Linux `/proc/self/status` `VmHWM`, the
  process lifetime RSS high-water mark, including attach, setup and the final
  sweep. Its `rss_source` identifies this source. Other platforms or unavailable proc
  data report both fields as `null`; they do not substitute a zero measurement.

Compare runs with the same provider, geometry, working set, seed, cache, FUA and
barrier policy. Host scheduling, the observer and backing storage affect real
elapsed time; the tool does not claim a hardware-independent speedup.

## Reproducible endpoint recovery scenario

The test harness uses interchangeable fake providers, an injected clock, a
20ms slow peer and a 2ms healthy peer. It compares concurrency 1, 2, 8 and 32
across healthy operation, a temporary slow-peer outage and recovery. Each phase
verifies all 64 results and records virtual elapsed time, p95/p99, pending input
bytes and global admission count/byte peaks. It verifies healthy-peer use,
failover, renewed admission of the recovered peer, and complete permit/timer
release. Fault phases begin only after the previous phase has completed.

```sh
cargo test --locked -p maki-benchmark --test synthetic_recovery -- --nocapture
```

These numbers use virtual time and measure the dispatcher's behavior. The
harness does not contact, pause or reconfigure operational endpoints. Run the
CLI separately for real provider/backing throughput; external power-loss or
deployment qualification remains a separate campaign.
