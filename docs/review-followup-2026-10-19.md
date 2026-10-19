# Review follow-up — 2026-10-19

The supplied review examined main at
`44d60ea4b133d4d5d19ed6ffc154f58b6dbd7784`. Its HTML report
(`maki-review-2026-10-19.html`) and reproduction archive
(`maki-review-reproductions-2026-10-19.zip`) were not available locally for
this change. The user's supplied report is the review context; its original
test totals and measurements are reported evidence, not tests rerun by this
pull request. The regressions below were added to the repository separately.

This document tracks F01–F09 remediation and the remaining work. It does not
change [current support](status.md): **production approval remains Pending**.
Historical [qualification reports](qualification/README.md) retain their
original revisions and scope. No new dirty-XFS VM, actual power-cut,
independent database ACK-ledger, or prolonged multi-volume campaign was run
for the evidence recorded here.

## F01–F09 changes and evidence

Implementation and qualification are separate. Each row names the changed
contract and the focused evidence to record; final integration results must
identify the tested revision and host. A focused regression does not certify
an entire numbered test proposal from the supplied report.

| Finding | Change | Focused evidence and remaining limit |
|---|---|---|
| F01 — Debian removal order | Generated `prerm` guidance and Debian README stop workloads, unmount/detach while the daemon accepts I/O, then allow shutdown's final drain/checkpoint. | Commit `ee77b59`; generated-message regression failed before the fix; all 15 Debian package tests passed. Actual dirty-XFS package removal remains unexecuted. |
| F02 — rejected encrypt response ownership | Erase every owned response allocation on encrypt-result validation failure, including spare capacity and earlier items when a later item fails. | Final evidence pending: `review_encrypt_response_zeroization.rs` and HTTP sensitive-response regressions. Allocator observations must inspect live allocations before deallocation; no disk disclosure claim. |
| F03 — plaintext echo-search cost | Replace repeated slice-window comparisons with linear-work substring matching while retaining the echo-rejection contract. | Commit `27fab14`; final evidence pending: exhaustive correctness, repeated-prefix and periodic near-match comparison-count regressions. No production latency claim. |
| F04 — WebSocket upgrade errors | Classify upgrade HTTP and TLS failures separately from transient transport I/O, retaining retry-safe dispatch rules. | Final evidence pending: `review_upgrade_errors.rs` and TLS tests; record the actual status/certificate cases and attempt/failover counts exercised. |
| F05 — volume UUID case | Compare hexadecimal volume UUIDs semantically in trusted attachment identity, mount/workload sentinels, and existing-sentinel retries. Preserve exact path and alphanumeric LVM-ID comparisons. | Commit `b4eefeb`; two regressions failed before the fix; all privileged-crate tests passed on Linux: 219 passed, 1 ignored. Includes all eight record/config/sentinel case combinations, serialized old records and rejection controls; no kernel NBD/LVM mutation. |
| F06 — large-record recovery memory | Treat 1 MiB as a batch target; apply full/oversized batches before scanning another payload, and write slot headers separately from payloads to avoid a ciphertext-sized copy. | Final evidence pending: target-boundary and consecutive 16 MiB ciphertext allocator regressions and recovery suites. Replay payload is bounded by the batch target plus one geometry-valid ciphertext; total RSS, metadata, providers and public all-record APIs remain separate. |
| F07 — gRPC connection-time cancellation | Complete shared connection readiness before submitting a plaintext-bearing unary request; preserve live sibling progress and align queued payload ownership with caller/admission lifetime. | Final evidence pending: stalled-TLS cancellation, timeout and live-sibling regressions in `protected_tests.rs`. Record actual deallocation and permit observations, not merely caller-task completion. |
| F08 — effective NBD listener | Validate an explicit configured socket against the native pathname listening descriptor before recovery/control binding/READY; reject disagreement and expose the effective `nbd_socket` in status. | Final evidence pending: native mismatch and matching-socket tests in `review_r3_native_startup.rs`. State whether native prerequisites were present; an early return is not native execution evidence. |
| F09 — durable extent reservation | Add a full data/allocation-metadata barrier immediately after slot reservation and before journal append, covering FUA, FLUSH and implicit-roll publication. Filesystem-backed files use `fsync` through `BackingFile::sync_all`. | Final evidence pending: `review_reservation_durability.rs`, barrier-failure controls and storage/release gates. The separate extent model distinguishes durable EOF from volatile reservations and exhausts space after crash. This conservative fix adds a shard sync per reservation; actual ext4/XFS power-loss behavior and performance remain unqualified. |

Final integration evidence: **pending**. Record final SHA, Linux/Rust
versions, package/native prerequisites, commands, exit statuses and bounded
log locations here after completion. Preserve failed reproductions separately
from successful post-fix runs and identify ignored or capability-skipped
tests.

## Current unresolved operational backlog

F10–F15 remain design and qualification work. No service identities, systemd
deployment, devices, LVM state or infrastructure were changed to address them
in this pull request. Existing nonce, trusted-record, topology, UUID and
fail-closed checks remain requirements for any follow-up.

| Finding | Design work | Acceptance on a disposable installed system |
|---|---|---|
| F10 — shared service identity; conditional P1 | Decide whether volumes share one trusted tenant. A stronger inter-volume contract requires per-volume identity, file/socket permissions and helper peer authorization together; `ReadWritePaths` alone is insufficient evidence. | T28: attempt sibling backing reads, socket use and signals under each service identity; demonstrate the chosen policy while normal data/control/helper access works. Do not claim tenant isolation before this decision and evidence. |
| F11 — killed/failed attach startup | Add failed-start cleanup to the service lifecycle using the existing trusted-record/live-kernel coordinator. Account for partial activation intent, idempotence and edited desired configuration before selecting an `ExecStopPost` entry point. | T26: kill the helper before/after every side effect; cleanup converges or fails closed with its trusted record retained, never mutates foreign resources or announces false readiness. |
| F12 — long checkpoint and deliberate stop | Define a stop budget and progress-driven deadline extension, plus stop intent that prevents recovery from restarting an intentionally stopped lifecycle. Do not assume a universal manager timeout. | T27/T34: slow backing and a large journal exceed the ordinary stop interval; acknowledged writes survive, the requested final state is inactive, and stop/recovery/reboot races preserve operator intent. |
| F13 — desired config versus current attachment | Provide an explicit current-record cleanup/inspection contract under the trusted lock. Reconstruct cleanup targets from the persisted attachment, while keeping configured detach/grow/verify strict about changed identity/pins. | T32/T54: edit each next-start field while attached, then clean up the original attachment safely; malformed/foreign records, changed live devices and removed pins retain their refusal behavior. |
| F14 — global lifecycle lock | Separate short shared NBD reservation coordination from per-volume lifecycle locks; define fixed-device conflicts and shared LVM-resource ownership before shortening lock coverage. | T33: stall one volume's filesystem/probe/sync and show another volume progresses within its own bound; concurrent automatic/fixed allocations never claim the same device. |
| F15 — later LVM mutation selectors; conditional P1, further verification | Carry verified device lists and VG/LV identity through ordinary deactivation and extension, with fresh checks at each mutation boundary. Reuse existing scoped activation/rollback/recovery patterns; do not substitute name-only lookup or weaken proof validation. | T29: same-name foreign VGs plus external autoactivation/replacement races either affect only the pinned resources or fail closed. No wrong-device mutation has been reproduced by this follow-up. |

The earliest installed-system work is dirty-XFS shutdown/removal (T25),
helper termination during attach (T26), and deliberate stop during a slow
checkpoint (T27). These are future acceptance campaigns, not completion
claims for this change.

## Improvement proposals I01–I27

These remain proposals unless a focused overlap above is explicitly stated.
Expected performance gains require measurement. The supplied report's
original IDs remain stable; this table maps all 27 without treating them as
newly implemented features.

| IDs | Follow-up scope |
|---|---|
| I01–I05 | Persist/reuse validated replay progress; reduce adopted-map, proven-prefix and overwrite metadata amplification; let healthy shards reclaim space when a peer punch fails. Preserve recovery durability before optimizing. |
| I06–I10 | Establish native allocation/hole-punch support and failure policy, geometry/FD preflight, shared orphan-metadata validation, discarded-unit damage reporting and cross-generation checkpoint/proof identity checks. F09's reservation barrier is only part of this scope. |
| I11–I15 | Measure blocking freshness checks, small-request fairness, cache metadata/allocator overhead, remote-witness RPC/manifest work and physical transport memory separately from logical plaintext admission. Keep freshness/fencing guarantees. |
| I16–I17 | Document each setting's consumer, application time, restart requirement and effective value; preflight helper/data-plane block sizes and bounded names/records before mutation. F08 addresses one socket mismatch only. |
| I18 | Measure callback/Tokio thread counts, RSS and context switching across worker settings and multiple volumes before changing defaults. |
| I19–I21 | Improve bounded incremental control framing, distinguish fatal engine latches from recoverable stalls, and expose accepted/durable/checkpoint progress, dirty age and remaining journal/overlay space. |
| I22 | Build a common transport contract harness for error classes, retry/failover, ownership/cancellation and size limits. F02/F04/F07 add focused regressions, not the full harness. |
| I23–I24 | Compare fuzz/production dependency resolution while retaining vendor provenance checks, and record capability-skipped tests separately from executed successes. |
| I25–I26 | Keep this short current backlog separate from historical remediation; bind future qualification to revision, package hash, host/filesystem/provider configuration, oracle and exercised scope. |
| I27 | Explain request versus response wire-size budgets, including base64, configured mappings, transport copies and admission accounting. |

## Test proposals T01–T56

All 56 are a campaign backlog. The overlaps below describe focused
repository regressions; their execution evidence belongs in the F01–F09
table and final integration record. They do not mean that all proposed
combinations or environments ran.

| IDs | Planned coverage and focused overlap |
|---|---|
| T01–T02 | Response-error cleanup and adversarial substring matching: F02/F03 implement focused owned-buffer/error cases and deterministic search-cost checks. |
| T03–T05 | TLS-connection cancellation, retained charge, live sibling and eventual timeout cleanup: focused F07 cases; broader queue/channel combinations still require the final evidence and transport harness. |
| T06–T07 | WebSocket HTTP/TLS classification: F04 adds selected status/certificate cases. Full Retry-After/backoff and every TLS-authentication configuration are not implied. |
| T08–T10 | Cancellation across serialization/send/body/trailers, earlier-item cleanup, and out-of-order batch errors: F02 overlaps T09; systematic cross-stage and scheduler coverage remains planned. |
| T11–T13 | Extent durability, repeated recovery interruption and large-record working sets: F09's separate extent model and F06's allocator regression cover subsets; actual power cuts, repeated interruption and full geometry/RSS qualification remain planned. |
| T14–T24 | Independent prefix/RMW correctness, combined metadata damage, restore mismatch, reclamation progress, tombstone ordering, replay-sync failures, extent-state modeling, FD limits, checker consistency and backing support: retain existing tests and add the proposed combinations in future campaigns. F09 overlaps the separate extent-state model in T21. |
| T25–T30 | Installed dirty-XFS removal, killed attach, deliberate stop, service isolation, LVM identity races and listener consistency: F08 adds native listener regressions for part of T30; the installed-system lifecycle matrix remains planned. |
| T31–T34 | UUID spellings, edited configuration, independent-volume progress and stop/recovery intent: F05 covers local old-record/sentinel case combinations for T31; installed attachment and lifecycle scenarios remain planned. |
| T35–T38 | Pre-open NBD negotiation limits, bounded names/records, block-size alignment and fatal/stalled health: planned. Existing related regressions do not qualify the proposed combined scenarios. |
| T39–T45 | Replay/metadata amplification, fairness, threads, cache overhead, transport RSS and witness cost: planned measurements; no throughput or latency improvement is claimed by this document. |
| T46–T50 | Deliberately broken-oracle controls, fuzz dependency parity, five 24-CPU-hour fuzz runs, standalone feature matrices and capability-removal gates: planned; ordinary regressions are not those long campaigns. |
| T51–T54 | Fixed-revision VM/device power cuts, independent DB ACK ledger, 72-hour mixed-I/O soak and retained-state upgrade: planned qualification, not run here. |
| T55–T56 | Execute shipped procedures and explore queue/permit/connection state models: F01 tests generated removal-message order only; whole installed procedures and systematic state-model exploration remain planned. |

Future campaigns should record independent ACK evidence and negative oracle
controls, distinguish restart/page-cache survival from power loss, and retain
failed or unexecuted outcomes. Existing fuzz targets, quorum CI and dated
campaign results are useful foundations; they do not replace the missing
acceptance evidence above.
