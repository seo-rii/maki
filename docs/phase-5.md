# Phase 5 — Backpressure, Retry, and HA

Status: **complete** · Gate criteria verified in-suite: queue bound violation = 0, permit leak = 0 (asserted via post-run `available_*` checks), retry storm = 0 (budget + jitter caps), bounded memory (100k requests through a 512-item queue)

## What was built (`maki-crypto` + engine admission in `maki-core`)

- **`flow::DualSemaphore`** — one semaphore bounding *both* request count and bytes (SPEC §30: "Limits MUST apply to both request count and byte count"). Oversized requests are capped to the whole budget (serialize, never deadlock); `try_acquire` rejects them. Permits are RAII — leak = 0 by construction.
- **`flow::BoundedQueue<T>`** — FIFO with item+byte capacity; `push` backpressures; capacity is released only when the item leaves the queue.
- **`retry`** — `full_jitter_delay` (`random(0, min(max, initial×2^attempt))`, SPEC §31) and `RetryBudget`: token bucket earning `retry_ratio` per initial request, capped at `burst`, with a **minimum probe rate** that keeps one retry per interval flowing even at zero budget (SPEC §32).
- **`breaker::CircuitBreaker`** — CLOSED → OPEN (after `failure_threshold` consecutive failures) → HALF_OPEN (limited probes after the open interval) → CLOSED on `success_threshold` successes / re-OPEN with the interval doubled up to `open_max` (SPEC §33). `would_allow()` peeks without consuming a half-open slot so endpoint selection doesn't burn probes.
- **`endpoint::EndpointSet`** — the multi-endpoint dispatcher, itself a `CryptoProvider`. Selection = circuit-admitted + least inflight (SPEC §34). Within one pass, a failing endpoint fails over to the next; between passes, full-jitter backoff gated by the retry budget. **Semaphores are held only around the RPC — never across a backoff sleep** (SPEC §31). Non-retryable/provider-fatal errors return immediately. `max_attempts: None` = `stall` policy, `Some(n)` = `bounded-error` (SPEC §35). Metrics: retries, failovers, per-endpoint circuit state and inflight.
- **`batch::Batcher`** — SPEC §30 batch scheduler: aggregates submissions to `target_items`/`target_bytes`, hard-capped at `max_items`/`max_bytes`, flushing at the latest after `max_wait`. (The engine currently batches per request and chunks to provider caps; the Batcher is available for cross-request aggregation at the adapter layer.)
- **Engine admission** (`EngineLimits`) — `max_active_callbacks` + `max_plaintext_bytes` acquired at `read`/`write` entry, completing the §30 pipeline: NBD → byte admission → (engine) → global semaphore → endpoint semaphore → RPC → journal.

## SPEC §47 test-first cases → tests

| Case | Test |
|---|---|
| global semaphore | `global_semaphore_bounds_concurrency` |
| endpoint semaphore | via `EndpointSet` per-endpoint `DualSemaphore` + dispatcher tests |
| byte semaphore | `byte_semaphore_bounds_total_bytes`, `oversized_acquire_is_rejected` |
| bounded queues | `bounded_queue_blocks_at_capacity_and_preserves_fifo`, `bounded_queue_enforces_byte_limit` |
| release permit during backoff | `permits_are_released_during_backoff` (1-permit config would deadlock otherwise) |
| full jitter | `full_jitter_is_bounded_and_spread` |
| retry budget | `retry_budget_limits_ratio_and_burst` |
| minimum probe rate | `minimum_probe_rate_survives_budget_exhaustion` |
| circuit transitions | `circuit_transitions_closed_open_half_open_closed`, `circuit_reopen_doubles_timeout_up_to_max` |
| endpoint failover | `endpoint_fatal_fails_over_within_one_call` |
| endpoint warm-up after recovery | `recovered_endpoint_warms_up_via_half_open` |
| queue saturation + FLUSH / + FUA | `saturation_respects_callback_limit_and_flush_fua_complete` (maki-core) |
| 100,000 pending requests | `hundred_thousand_requests_through_bounded_queue` |

Plus `non_retryable_errors_fail_fast` (retry storm = 0 for permanent errors) and `byte_admission_bounds_inflight_plaintext` (provider concurrency ≤ 1 under a one-unit byte budget, then a full-size write proves no leak).

## Decisions of record

- Failover on `Retryable`/`Throttled`/`EndpointFatal` all happens *within* a pass (before any sleep); only a fully failed pass backs off. This keeps ManualClock-driven tests deterministic and matches §34's "healthy + closed + least inflight" selection on every attempt.
- `would_allow`/`allow` split on the breaker prevents endpoint *selection* from consuming half-open probe slots.
