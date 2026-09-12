# Status and metrics during storage stalls

`maki status <config>` and `maki metrics <config>` read in-memory observations.
They do not refresh filesystem free space or wait for a volume operation or
cache eviction to complete. This keeps a blocked checkpoint or `statvfs`
from also blocking the information needed to diagnose it (MAKI-039).

Status reports these observation boundaries:

| Field | Meaning |
|---|---|
| `state` | `ready` or `degraded` when the volume metadata can be observed immediately; `busy` while its lock is unavailable |
| `last_observed_state` | Engine state associated with the reported volume metadata; a cached `ready` value does not establish current readiness |
| `observability.volume_snapshot` | `current` for an immediate metadata observation, or `cached` for the last completed journal/flush/checkpoint observation |
| `observability.volume_snapshot_age_ms` | Age of that volume observation, using the engine's monotonic clock |
| `observability.backing_space` | `cached` after an operational free-space query completes, or `unavailable` before one has completed |
| `observability.backing_space_age_ms` | Age of the free-space sample, or `null` when unavailable |
| `observability.cache_snapshot` | `current` when cache statistics can be observed immediately, otherwise `unavailable` |
| `io_state`, `drain_error` | Current admission/drain state, independently of the volume metadata observation |

Journal sequences, journal size and overlay size come from one volume
observation. When it is cached, those values remain the last observed values;
they are not reset to zero. Admission, latency and checkpoint counters are
sampled separately and may already include newer activity. The response is
an observation of those components, not a transaction across all of them.
An increasing snapshot age during `busy` indicates that a volume operation
has not yet published its result.

Free-space values are always cached and may be outdated. `null` means the
backing did not provide a measurement or no measurement is available. Status
never initiates a free-space query. It must not be used for capacity admission.

Metrics expose the same limitations through `maki_volume_busy`,
`maki_volume_snapshot_age_seconds`,
`maki_backing_space_sample_age_seconds` and `maki_cache_stats_available`.
`maki_volume_state` is `null` while busy; existing codes remain 1 for ready and
2 for degraded when immediately observable. Cache counters and sizes are
`null` when their observation is unavailable. Consumers must preserve these
unknown values rather than treating them as zero or ready.

Status is not a readiness gate for starting a workload and does not replace
the acknowledged drain result. A blocked process, exhausted runtime threads,
CPU starvation, or an unreachable control socket can still prevent a reply;
an external monitor must enforce its own response deadline. This change
removes storage-lock and storage-query dependencies from the monitoring path;
it does not isolate the control service into a separate process.

The regressions in
[`review_r3_monitoring.rs`](../crates/maki-nbdkit/tests/review_r3_monitoring.rs)
hold a drain's backing sync and a free-space query independently, verify that
status and metrics return before either is released, and then release and
join every fixture worker. They also verify that a first status request does
not invent a free-space observation.
