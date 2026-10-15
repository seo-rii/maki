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

## Request counts and latency boundaries

| Metric | Meaning |
|---|---|
| `maki_active_requests` | Public Engine read, write, trim and flush calls still waiting or executing; one request may run multiple provider batches |
| `maki_admission_slots` | Retained admission permits, including extra parallel batches and storage that continues after its caller is cancelled |
| `maki_active_callbacks` | Compatibility alias of `maki_admission_slots`; it is not the number of public requests |
| `maki_requests_success_total`, `maki_requests_error_total`, `maki_requests_cancelled_total` | Exactly one completed outcome per started Engine call; unwinding counts as an error |
| `maki_request_seconds` | All public Engine calls from first poll through return or cancellation, including validation, provider, admission, unit/volume locks and blocking-pool waits |
| `maki_read_request_seconds`, `maki_write_request_seconds`, `maki_trim_request_seconds`, `maki_flush_request_seconds` | The same complete interval split by operation |
| `maki_fua_request_seconds` | Complete write/trim calls submitted with FUA, including unsuccessful outcomes |
| `maki_journal_sync_seconds` | Actual explicit storage-barrier time, including failed FLUSH/FUA, inline admission barriers and the background checkpoint worker |
| `maki_flush_seconds`, `maki_fua_seconds` | Existing successful storage-only series; their names and sample semantics remain compatible |

Latency series export `_sum`, `_count` and `_max`. Complete request series
include successful, failed and cancelled calls. For example, an FUA write that
spends 2s at the provider and 4s in a failed sync contributes 6s to complete FUA
request time and 4s to journal sync time, while the legacy successful-FUA count
stays unchanged. A FLUSH waiting 3s for the volume before a 4s failed sync
records 7s of complete request time.

A caller cancellation can leave `maki_active_requests = 0` and
`maki_admission_slots = 1` while already-dispatched storage finishes. This is
retained work, not a request or permit leak. Internal trim chunks and its
barrier count as one trim; the convenience `Engine::read` counts once through
`read_secret`.

These request clocks begin at Engine entry. Adapter validation, buffer copies
and NBD chunks before/around that entry are outside the interval; a larger NBD
callback may issue several Engine calls. Automatic journal segment rolls are
inside complete request latency but are not separate explicit journal-sync
samples. Provider processing remains the dispatcher's
`maki_crypto_latency_seconds` completed-attempt series. Use these boundaries
when attributing a wait; the series do not form an additive partition of a
request.

## Logs

Status and metrics answer "what is the state now"; the log answers "why".
The plugin and the `maki`, `maki-check` and `maki-attach` binaries install a
stderr `tracing` subscriber at startup (default threshold `info`, `MAKI_LOG`
overrides; `maki-benchmark` and `maki-witness` install none), so
checkpoint and journal-sync failures, provider quarantine, store repairs and
control-server errors appear in `journalctl -u maki@<volume>.service` with
their level and target. A `state: degraded` in `maki status` therefore has a
matching `WARN` line with the underlying error class. A failed NBD request
(read, write, flush, trim or zero) is logged as a `WARN` `request failed` line
with the operation, offset, length, errno and error, at most once per second;
the next line counts the ones suppressed in between. Payload bytes are never
logged. See [operations: logging](operations.md#logging).
