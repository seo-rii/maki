# Boundary review follow-up — 2026-10-15

This is a map of reviewed changes and evidence, not a release approval.
At the start of this review, remote `main` was
`0cc3539c9af9671099e5c7d2cdf19cbc99977d58`.
Local `main` at `b268798` contains five additional commits; neither the local
branch nor an open PR establishes that the changes are merged remotely.

The review identified three separate questions: whether a patch exists, whether
its regression closes the reported counterexample, and whether the complete
combination passes qualification. Keep those states separate below.

## Previous findings

| Review | Change / prerequisite | Regression evidence | Implementation commit | Remaining boundary |
| --- | --- | --- | --- | --- |
| R-01 | [#56](https://github.com/seo-rii/maki/pull/56), after #49; [#59](https://github.com/seo-rii/maki/pull/59) after #9 | Admission before freshness/copy, cancellation retains permits; 47 focused tests plus strict Clippy passed | `822e724`, `2b36f4a` | Partially addressed: nbdkit pre-open negotiation resources remain upstream-owned |
| R-02 | [#48](https://github.com/seo-rii/maki/pull/48) | `review_discard_storage`: live tombstones across shards, all-discarded, overlay priority, v2 empty ciphertext; 12 passed | `0adcad2` | Live Volume API regression; does not assert ordinary restart always failed |
| R-03 | [#49](https://github.com/seo-rii/maki/pull/49), after #44 | `review_blocking_io`: current-thread runtime progress, canary load/store offloading, cancellation retains volume lock; 11 passed plus checkpoint 7 passed | `74f191e`, `b36a3eb` | Public `verify_key_canary` now owns an `Arc<Volume>` |
| R-04 | [#44](https://github.com/seo-rii/maki/pull/44), after #43 | `review_checkpoint_concurrency`: 128 cancelled gate waiters, active publication survives cancellation; 7 passed | `55a62b9` | Direct Engine API scope, separate from control-socket serialization |
| R-05 | [#45](https://github.com/seo-rii/maki/pull/45) | `maki-cache` suite: 10,000 empty keys, version ordering, randomized model | `d70f8e8` | Payload budget bounds positive-size entry count, not total allocator overhead |
| R-06 | [#58](https://github.com/seo-rii/maki/pull/58) | Benchmark oracle rejects the previous plaintext generation returned through a real Engine; hot-address ordering, failed writes, bounded oracle preflight; 17 tests and strict Clippy passed | `21a86c4` | Benchmark oracle is not storage durability qualification |
| R-07 | [#54](https://github.com/seo-rii/maki/pull/54), completed at the public pre-claim boundary by [#69](https://github.com/seo-rii/maki/pull/69) | Loader faults (4) and public remote rollback suite (17) passed; attach/takeover retain I/O kind and errno, preserve authority and allow retry after storage repair | `564c702`, `f75ec5e` | Independent of transient witness freshness handling in #15 |
| R-08 | [#60](https://github.com/seo-rii/maki/pull/60), after #59 | Docs matched to native chunked writes/zeroes and rejection rules; #59 native/limit 7 tests plus ABI and strict Clippy passed | `51c9fe4` | Advisory NBD maximum and per-engine-call maximum are different |
| R-09 | [#46](https://github.com/seo-rii/maki/pull/46), after #45 | Returned Arc survives lazy TTL eviction; final owner releases buffer | `bf2d72a` | TTL/eviction is not an immediate plaintext-erasure deadline |

## Additional findings

| Review finding | Change / prerequisite | Regression evidence | Implementation commit |
| --- | --- | --- | --- |
| Witness live resource count | [#52](https://github.com/seo-rii/maki/pull/52), after #26 → #16 | Actual authenticated TLS waiters, task handles and TLS lifetime during eviction churn; 31 tests passed on this head | `7616d3f` |
| Witness thread-spawn failure | [#53](https://github.com/seo-rii/maki/pull/53), after #52 | Inject first spawn failure, then successful real TLS RPC on same listener; 32 tests passed on this head | `e604c47` |
| Serialized transport sizes | [#57](https://github.com/seo-rii/maki/pull/57), after #4; config fixture #64 | Format config (25), gRPC phase9 (10) and integrity/self-test (6), WebSocket phase9 (8), HTTP encoding/mod-3/full-batch (2) plus numeric-array/escape (2), request serializer and strict Clippy passed | `0a53a20` |
| Safe configuration errors | [#50](https://github.com/seo-rii/maki/pull/50), after #28 | Parser Display/Debug (6 passed), actual CLI stdout/stderr (1 test / 4 cases) with backticks, numbers, escapes and unknown keys | `526327a` |

NBD plugin-handle admission is enforced at open/close: the native regression
refuses 16 additional clients and accepts a replacement after close. nbdkit
owns negotiation sockets and threads before plugin open, so R-01 is not a
claim of a global pre-authentication or pre-negotiation process-resource cap.

Witness capacity charges survive ticket eviction and TLS teardown. Pending
handshakes are bounded at four per worker and total connection tasks at five
per worker; the accept loop may hold one additional socket without a TLS task.
The regression uses authenticated clients and is not evidence of a measured
unauthenticated Internet attack.

Configuration parse errors retain only a fixed classification and source
location. Unknown key names are untrusted input too; no free-form TOML/Serde
message is exposed. This protects rejected input, not extraction from a normal
credential file.

Transport JSON bounds cover compact declared shapes, including the required
null prefixes for numeric JSON Pointer array indices. Invalid pointer escapes
are rejected. gRPC also budgets the mandatory singleton profile self-test,
whose extended profile can cross a protobuf length boundary. Unmapped fields,
additional array siblings, extra whitespace or redundant escaping need
headroom and remain subject to the hard runtime cap. Tests exercise actual
serializer/transport boundaries, not only arithmetic config acceptance.

## Known operational items

- [#51](https://github.com/seo-rii/maki/pull/51), commit `77d2485`, corrects
  shutdown instructions to allow unmount writes before closing admission.
  A dirty-XFS full lifecycle campaign on the final integrated revision remains
  pending. Existing packaged stop ordering was inspected, not redeployed.
- Repeated recovery timeout/OOM convergence remains pending. Bounded replay
  payload memory is not evidence of persistent progress across repeated kills.
  Measure cumulative I/O, restart count and final external ACK agreement.
- Partial attach cleanup has prior scoped qualification; it is not a proof for
  every interruption point or topology. Final-revision step-by-step NBD/LVM
  cleanup convergence remains pending. Local risk entries ARCH-002/ARCH-003
  retain these distinctions.
- [#55](https://github.com/seo-rii/maki/pull/55), commits `c629b3e` / `3e1b1be`, refuse
  `volume inspect`, `check`, and `check --deep` on remote rollback backing,
  before an implicit writer claim. Actual CLI/TLS tests preserve authority
  state and namespaces in both Active and Released states. The full remote
  administration suite passes (10 tests), including explicit test ownership
  for initialized-superblock checks and authority-only frontend failover. A dedicated
  read-only ciphertext view is still unsupported; `volume witness` only
  inspects the authority and is not an integrity check.
- [#61](https://github.com/seo-rii/maki/pull/61), commit `d6be54e`, retires
  unresponsive established gRPC channels on retryable failures and cancellation.
  A blackhole proxy regression failed before the fix; all 65 gRPC tests and
  strict Clippy passed afterward. Initial TLS negotiation retains its bounded
  progress window; identity checks protect a newer channel from stale failures.

## Integration and CI

[#47](https://github.com/seo-rii/maki/pull/47), commit `0f70cac`, builds on #1
and enables release/native plus an independent real etcd qualification job for
`review/integration-*` PRs and manual runs. It verifies the upstream etcd
v3.6.5 archive SHA-256, requires matching etcdctl, and builds the witness
frontend from the checked-out revision. Native checks still run after a phase
gate fails; errors remain failures.

The previous scheduled run [38535737579](https://github.com/seo-rii/maki/actions/runs/38535737579)
ran on remote main. Nightly lacked `MAKI_ETCD_BIN`. The Windows latest-stable
log shows timeouts in
`same_writer_certificate_cannot_reuse_its_old_key_after_admin_enrollment_recovery`
and `state_rpc_enforces_authenticated_roles_and_preserves_cas_conflicts`.
[#37](https://github.com/seo-rii/maki/pull/37) adjusts witness fixture deadlines;
both Windows jobs passed in the integration run described below.

The first local combination (`9899175`, PRs #1–#55) ran
`cargo test --workspace --locked --no-fail-fast` and exited 101. Two remote
administration tests still expected the newly prohibited implicit writer claim;
the follow-up preserves initialization and failover coverage using explicit
fixture ownership and authority-only inspection. The crypto stress fixture continuously injected errors on every peer while
requiring success; a deterministic fatal preseed reproduced zero successes.
[#62](https://github.com/seo-rii/maki/pull/62), commit `99f035b`, bounds the
random fault campaign and verifies all-down refusal followed by real recovery
with a manual clock, while preserving immediate circuit opening for fatal
endpoint errors. Fifteen focused tests and strict Clippy passed on its head;
the same patch on the initial integration also passed five stress repetitions. Four native test targets hit the real backing
free-space guard on the local temporary filesystem; their rerun uses a
filesystem with sufficient space, without lowering the production guard.
This first run is not a successful integration claim.

A later local combination (`ae67f04`, latest PRs #1–#61) passed the affected
native suites, core blocking/checkpoint suites, workspace strict Clippy, format
and diff checks. CI/security/lifecycle/doc-link contract checks passed (19
tests). Full transport validation found a prior request-size config fixture
still accepting a 600-byte message with a 128-byte profile, which now correctly
requires 704 bytes. [#64](https://github.com/seo-rii/maki/pull/64), commit `f1ec484`, keeps the
original direct-provider encoding-boundary regressions and derives config
headroom from actual normal/probe protobuf lengths (8 regressions and strict
Clippy passed). This stage is not recorded as a full pass.

The next local combination (`8e81ab9`, including #62–#64) passed the
crypto/format/HTTP/WebSocket/benchmark/witness/CLI suites and all gRPC targets
except the stalled-TLS handshake test. This exposed existing implicit rustls
provider selection when both ring and aws-lc features are unified. The
selection rule is unchanged between rustls 0.23.45 and 0.23.46. A full workspace
build had hidden this path through nbdkit's dev-dependency enabling tonic's
explicit TLS backend; a selected-package build did not include that feature. [#65](https://github.com/seo-rii/maki/pull/65), commit `26c88e3`, explicitly
selects tonic's ring fallback while respecting an installed global provider.
Its CI follow-up `da9b5e4` runs gRPC alone with both TLS backends so unrelated
workspace dev features cannot conceal a missing production dependency.
The isolated no-global-provider test reproduced the panic with both backends,
then passed after the fix; five TLS contract tests and strict Clippy also
passed. [#66](https://github.com/seo-rii/maki/pull/66), commit `2e54b1b`,
applies explicit fallback selection to WebSocket, with isolated no-global
provider and installed-provider regressions (8 TLS tests plus strict Clippy
passed). Default roots still reload on reconnect; configured TLS connectors
retain their existing caching behavior. Neither fix changes an installed
process-global provider.
Workspace strict Clippy, fresh
`cargo audit --deny warnings`, 29 vendor/CI/documentation contract checks,
source-provenance verification, documentation links, fmt and diff checks all
passed. The aggregate test command exited 101 until that TLS initialization
issue is fixed.

The final local code combination `24aed52df287409f4b8a562aa0a98c13c1fd9e9e`
contains PRs #1–#66. All of the following completed with exit 0:

- Full tests for `maki-crypto`, `maki-format`, `maki-crypto-grpc`,
  `maki-crypto-http`, `maki-crypto-websocket`, `maki-benchmark`,
  `maki-witness` and `maki`, with `--locked --no-fail-fast`.
- The isolated gRPC stalled-TLS regression with both rustls backends enabled.
- `cargo clippy --workspace --all-targets --locked -- -D warnings`.
- Fresh `cargo audit --deny warnings`.
- Vendor, CI, lifecycle and documentation contract checks (29 Python tests),
  vendored-source provenance verification, documentation links, fmt and diff.

The native and core blocking/checkpoint suites previously passed on `ae67f04`;
the later code changes concern TLS backend selection, dependency updates and
test fixtures. This local evidence does not substitute for a fresh full
workspace/release/native/etcd run on the final integration revision.

The first remote integration run [38718662162](https://github.com/seo-rii/maki/actions/runs/38718662162)
tested candidate `d24960e187822087bc067ef6e78e4736c3a60135` at GitHub merge
checkout `c5b3b680acc4abb3337f212e107c6047c6e18a9f`. Both Windows jobs,
latest-stable Ubuntu, release/native gates and real etcd qualification passed.
Baseline Ubuntu also passed audit, Clippy and workspace tests, then failed the
Python dependency-feature contract: gRPC's paused-clock tests lacked a direct
dev-only Tokio `test-util` declaration. Commit `ebda86e` supplies that feature;
all three connection tests, the complete 74-test validation-script discovery,
36 package/release/documentation tests, fmt and diff checks passed locally.
The original integration run remains a failed run.

Merge review found that the public attach/takeover wrapper still converted
loader I/O errors to `InvalidData`. [#69](https://github.com/seo-rii/maki/pull/69)
keeps the root/witness mismatch context only for corruption. Both new public
regressions failed before the fix and passed afterward; authority and a live
writer remain unchanged on an actual storage error, and retry succeeds after
repair. All 17 remote rollback tests, four loader fault tests and strict
Clippy passed.

The workflow follow-up `00558d6` restricts branch-name opt-in to PRs from this
repository. A fork named `review/integration-*` cannot opt into release/etcd
jobs through that condition. Scheduled and manually dispatched qualification
remain enabled; event/repository/branch cases cover both jobs.

[#70](https://github.com/seo-rii/maki/pull/70), commit `d67152f`, treats a
completed nonretryable or throttled gRPC response as an established connection.
Otherwise the first error response left the initial handshake grace period in
force and delayed retirement after a subsequent blackhole. The live regression
covers success, InvalidArgument and ResourceExhausted followed by timeout or
cancellation; it failed before the fix. Twelve integration tests, three
connection tests and strict Clippy passed.

[#71](https://github.com/seo-rii/maki/pull/71) aligns configuration diagnostics,
all published shutdown recipes and the witness eviction/lifetime contract with
the integrated behavior. Routine target stop keeps admission open for unmount;
explicit drain acknowledgement follows unmount while the daemon remains alive.
The key-rotation procedure also accounts for systemd stop propagation. Sixteen
documentation contract/link tests and the complete link check passed. This is
procedure consistency, not new dirty-XFS qualification evidence.

The automatic review's suspected unbuffered TLS KeyUpdate ordering failure on
#63 was not reproduced. Existing `check_required_size` includes queued TLS
records and `write_fragments` copies them before encrypting application data.
[#72](https://github.com/seo-rii/maki/pull/72), commit `4a3712d`, adds real-peer
low-record-limit regressions for direct output and exact-size retry after an
insufficient buffer. Both ring and AWS-LC library suites passed (265 and 266
tests); vendor provenance and contract checks passed. Production encryption
and output logic are unchanged.

[#73](https://github.com/seo-rii/maki/pull/73), commit `e242d85`, starts the
WebSocket connection deadline before TLS/root preparation. An exhausted budget
does not open a socket; otherwise network setup uses the remaining time.
Both deadline regressions failed before the fix; all 80 WebSocket tests,
dependency-feature checks and strict Clippy passed. Final review then found
that direct deadline addition panicked for a timeout such as `Duration::MAX`,
which Tokio's prior relative timeout accepted. [#74](https://github.com/seo-rii/maki/pull/74),
commit `cdef14f`, uses checked addition and preserves that behavior. The real
local handshake reproduced the panic before the fix; all three deadline tests
and strict Clippy passed afterward. Native-root discovery remains synchronous
and cannot be preempted by this deadline.

The intermediate candidate `6b7d0cb` started run
[38733755607](https://github.com/seo-rii/maki/actions/runs/38733755607).
That run was cancelled when the final review required further fixes; its
completed etcd job is not a complete qualification result.

The final integration review also found that global control-socket option
parsing intercepted the privileged helper's NBD `--socket` argument.
[#75](https://github.com/seo-rii/maki/pull/75), commit `85c72cf`, preserves raw
attach/detach/grow arguments before control parsing, as well as the existing
leading-timeout fallback. The actual CLI regression failed before the fix;
seven CLI tests and strict Clippy passed afterward.

[#76](https://github.com/seo-rii/maki/pull/76), commit `d1c9554`, preserves the
space-refusal trigger when a failed physical reclamation hint has retained a
cursor but all journal records are already gone. The regression failed before
the fix; it now verifies exactly one attempt per refusal without autonomous
retry, then actual slot reclamation and a successful write after fault repair.
All 31 related tests and strict Clippy passed. Existing checkpoint backoff and
immediate-retry suppression are unchanged; stalled physical release still
requires another checkpoint reason, such as space refusal, rather than the
interval alone.

[#68](https://github.com/seo-rii/maki/pull/68) combines the reviewed PR heads
while preserving each change's commits. Its description records the final
candidate, complete CI run and eventual merge revision. Use that exact result
instead of adding test counts from different branches. The integration run
above predates the final review follow-ups and does not qualify them.

Dependency examples retained: #26 → #16; #27 → #22; #35 → #9; #43 → #18;
#44 → #43; #49 → #44; #52 → #26; #53 → #52; #50 → #28; #46 → #45;
#47 → #1; #51 → #41; #56 → #49; #57 → #4; #59 → #9; #60 → #59;
#61 → #30; #62 → #3; #65 → #30. #64 must accompany #57 to update an older config
acceptance fixture; its direct-provider overflow regressions are retained. Follow-up PRs name their immediate base in GitHub.

### Dependency audit follow-up

The completed [baseline Ubuntu job for #53](https://github.com/seo-rii/maki/actions/runs/38709664716/job/116337632597)
failed `cargo audit --deny warnings` for the then-pinned `rustls 0.23.45` before
workspace tests. Its four advisories, published 2026-10-14, specify
`>=0.23.46` as the fixed range:

- [RUSTSEC-2026-0347](https://rustsec.org/advisories/RUSTSEC-2026-0347): buffered application data after ECH rejection.
- [RUSTSEC-2026-0348](https://rustsec.org/advisories/RUSTSEC-2026-0348): excessive unauthenticated Brotli certificate allocation.
- [RUSTSEC-2026-0349](https://rustsec.org/advisories/RUSTSEC-2026-0349): subsequent key-exchange downgrade.
- [RUSTSEC-2026-0346](https://rustsec.org/advisories/RUSTSEC-2026-0346): TLS secrets in session Debug implementations.

[#63](https://github.com/seo-rii/maki/pull/63), commit `166969f`, updates the
verified upstream release to 0.23.46 while retaining all seven local erasure
source patches and refreshing lockfiles and provenance inventories. No advisory
is ignored or suppressed. Fresh `cargo audit --deny warnings`, vendor contract
checks, both ring/aws-lc library suites, live HTTP/WebSocket/gRPC TLS tests and
Brotli/zlib compression regressions passed (545 Rust tests, 11 Python checks,
plus documentation links). The erasure delta and new upstream production paths
received independent review. This removes the reproduced dependency blocker
on that PR head; it does not establish that the complete combined CI passes.
