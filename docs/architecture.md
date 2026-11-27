# Architecture

Maki turns encrypted backing files into a byte-addressed Linux block device.
The storage engine does not require a specific cipher: cryptography is supplied
through a checked provider contract and may run locally or over the network.

## Data path

```text
Application or database
        |
       XFS
        |
       LVM
        |
   /dev/nbdN
        |
Linux NBD client
        |
     nbdkit
        |
  maki-nbdkit
        |
    maki-core -------- CryptoProvider
        |               |-- local AES-GCM-SIV / AES-XTS
encrypted backing       `-- HTTP / WebSocket / gRPC
```

The long-running data plane owns one volume. The separate `maki-attach` helper
performs privileged NBD, LVM, mount, and growth operations and never receives
crypto credentials.

## Components

| Crate | Responsibility |
|---|---|
| `maki-core` | Reads, writes, journaling, checkpointing, recovery, admission control, and metrics |
| `maki-format` | Configuration schema and versioned on-disk metadata |
| `maki-backing` | Escape-safe backing namespace and positional file I/O |
| `maki-crypto` | Provider contract, validation, flow control, retry, circuit breaker, and failover |
| `maki-crypto-*` | Local, HTTP, WebSocket, and gRPC provider implementations |
| `maki-cache` | Versioned plaintext read cache |
| `maki-nbdkit` | Blocking adapter, daemon assembly, and Linux C ABI shim |
| `maki-control` | Unprivileged control socket protocol |
| `maki-privileged` | Auditable attach, detach, mount, and growth plans |
| `maki-witness` | Remote witness client and server, etcd quorum store, and frontend failover |
| `maki-test-support` | Durability oracle, crash backing, fake provider, manual clock, and failpoints |
| `maki-fuzz-harness` | Entry functions of the `fuzz/` targets and the generator of their committed seeds |

## Backing namespace

Linux `FileBacking` resolves paths through pinned directory descriptors without
following symlinks. Each file open checks the opened descriptor for a regular
file with exactly one hard link, including existing files opened with creation
enabled and volume lock files. This rejects existing aliases to another backing
file or a file outside the root before returning a writable handle, using the
same single-link policy as remote namespace garbage collection. Hardlink-based
backing copies are unsupported while the extra links exist; see the
[backing support requirements](deployment/support-matrix.md#backing-store-below-maki).

The link count is checked only when a file is opened. A process able to change
the namespace can add a hardlink after that check, and previously returned
handles remain usable. This check does not isolate the backing from an actor
with permission to modify its namespace or inodes; deployment must protect
them through filesystem permissions and ownership. Non-Linux development
backends retain pathname validation and do not provide this single-link check;
the supported data plane is Linux-only.

A process running as root (an offline check, inspect, creation or remote
administration command) creates each file and directory below the backing
root for the owner of the directory it creates it in, when that owner is not
root, so a lock file or manifest slot it recreates in the daemon user's tree
stays openable by the daemon. A new file is created unnamed (`O_TMPFILE`),
given away and synced with fsync before it is linked under its name; on a
filesystem without unnamed files it is created under its name and given away
before anything is written to it. A directory cannot be created unnamed: after
`mkdirat`, the directory its name holds is given away only while it is empty
and root's, whichever root process made it, so nothing that holds an entry or
belongs to another user changes owner. An entry that already exists is opened
as it is and never changes owner, and a refused owner change removes what was
created. A crash between creating an entry and giving it away (a directory, or
a file created under its name) leaves an empty root-owned entry that later
runs open as it is, and the entries they create in such a directory are
root's too. The backing root itself, when `FileBacking::new` creates it,
belongs to the user that runs the process. The local witness directory
follows the same rule, and its record is never published from a file another
user may hold open: a leftover `anchor.next` is removed first, and a file
that a user other than root or the record's owner puts back under that name
meanwhile is refused.

Volume, rollback, witness, attach and control-socket directory locks are
`flock` locks on descriptors opened close-on-exec. Such a lock belongs to the
open file description, which every child process forked by any thread shares
until its `exec` closes its copy. Each lock guard therefore unlocks before
closing its descriptor: a close alone would keep a released lock held for such
a child, and a reattach in that window would fail as `VOLUME_ALREADY_ATTACHED`.

## Read and write semantics

The engine divides the device into fixed crypto units. Reads take a consistent
ciphertext snapshot per unit, decrypt in provider-sized batches, and return
zeros for unallocated units. A racing read observes either the old or new unit,
never a torn mixture.

Writes lock touched units in ascending order. Partial-unit writes perform a
read-modify-write, encryption happens outside the volume lock, and ciphertext
records are appended to the journal before becoming visible. FUA synchronizes
the complete request; FLUSH is an ordered durability barrier for all preceding
writes.

## On-disk state

| Structure | Protection | Role |
|---|---|---|
| Superblock | Two generations plus CRC; new volumes use envelope v2, or v3 when created with discard support | Volume identity, geometry, provider type, key name, compatibility ID, and required recovery policy |
| Key canary | Two generations plus CRC, written at first attach | Provider/key-bound ciphertext of a fixed plaintext; must decrypt on every attach |
| Shard catalog | Two generations plus CRC | Durable set of allocated shard files |
| Allocation map | Per-shard A/B copies | Distinguishes unwritten units from allocated slots |
| Slot | Header CRC and ciphertext CRC | Stores one encrypted unit and write sequence |
| Journal segment | Header and record CRCs | Ordered ciphertext writes pending checkpoint |
| Journal durable proof | Two 64-byte CRC records, both published before a barrier succeeds | Required sequence and exact segment/record-end boundary for v2 recovery |
| Legacy journal durable mark | CRC, single advisory copy | Retained advisory metadata; does not replace or weaken the v2 proof requirement |
| Checkpoint state | Two generations plus CRC, written at creation | Highest durably applied journal sequence |

Metadata updates select an absent, invalid, or older A/B side for replacement.
Before touching it, the store rewrites the preserved, typed-valid copy's exact
bytes without truncation, synchronizes that file, and synchronizes its parent
directory. A replacement side that exists but does not decode (a torn or
damaged copy) is then truncated to zero length and synchronized: an earlier
interrupted store wrote it with the generation this store will use, and
without this step the sectors of that store which reached the disk could
combine with the sectors of this one into a valid copy of the earlier record.
A side that decodes is never emptied. Only then does the store advance the
generation, write the replacement, and synchronize the new contents. The
caller must synchronize the replacement's directory entry when it creates a
file. Each store advances the generation by
one, and recovery and the deep check refuse a volume whose A/B metadata carries
a CRC-valid generation in the top quarter of the generation space (above
`u64::MAX - 2^62`) before any recovery write: no writer produces one, and
`2^62` stores below the store's own exhaustion check no attach, replay or later
checkpoint can exhaust a generation.

This preservation step also runs after a failed store or a process restart:
readable, CRC-valid bytes may still be volatile, and writeback errors can clear
dirty page-cache bits without persisting them. If preservation fails, the
replacement side is untouched. A torn replacement can therefore fall back to
the preserved generation. A side that is absent, empty, short, or fails its
CRC or typed decode is an invalid copy; any other read error is an I/O error
and refuses attach rather than silently selecting the other side.

The required durable-proof store prevalidates future versions and semantic
consistency before using A/B storage. It performs two publications of the same
horizon, including directory syncs, so both copies attest every successfully
acknowledged boundary. One ordinary A/B update would leave the fallback horizon
behind an ACK. Unsupported proof versions, contradictory generations and
regressing horizons therefore fail explicitly rather than selecting or
overwriting a convenient older side.

Envelope v2 is distinct from the crypto AAD's `format_version`. Old binaries
reject v2; the current writable recovery path refuses legacy v1. Read-only
legacy inspection remains available with a warning. The
[compatibility and migration procedure](durable-recovery.md) requires a separate
verified data migration; there is no automatic in-place upgrade.

## Recovery and checkpointing

New volumes can explicitly select metadata envelope v3 for discard support.
V2 creation remains the default. V3 adds replicated discard bitmaps and journal
tombstones, preserving the crypto context and required durable proofs. The
[space reclamation protocol](space-reclamation.md) specifies logical zero reads,
bitmap publication, physical hole punching and replay ordering.

Recovery acquires the volume lock, checks the superblock envelope and required
proof, validates allocation state, loads checkpoint state, scans journal segments,
and, once the checks and repairs below succeed, replays the records newer than
the checkpoint into their slots in bounded batches, advances the checkpoint and
removes the segments it then covers. The volume starts with an empty overlay.
Recovery fails closed: the oldest surviving segment must bridge from the checkpoint
boundary, segments must be contiguous and carry the volume's UUID, a segment
larger than the writer can produce is rejected before it is read, and a
complete-but-invalid segment header is treated as damage rather than as a
creation crash. The writer never extends a new segment before its header
write, so a header write that persists only a prefix leaves a final file
shorter than a header (or all zero), which recovery discards as a creation that
never completed. Writers that preallocated the header could instead leave a
final segment exactly one header long whose header fails its checksum; recovery
discards that too, but only at an index above every segment the durable proof
and mark name. The proof names the segment of the newest acknowledged record
and the mark names a segment only once its creation completed, so such a file
holds nothing acknowledged. Every other invalid header still fails closed.

The journal above the selected checkpoint must bridge through the proof's
required sequence and exact record-end offset before recovery changes metadata.
A missing final segment, a shortened complete-record prefix, or corruption
inside that required prefix fails explicitly. A proof may name a pruned segment
only when the checkpoint already covers its horizon. Both proof copies absent
or invalid is an error even for an empty-looking v2 volume.

The first recovery write makes the selected superblock durable. A creation that
failed or was killed after writing superblock A (a failed fdatasync, or a kill
before it) leaves a readable copy that may exist only in the page cache, and a
retried creation refuses that root, so recovery is where the copy becomes
durable. It rewrites each valid copy from its exact validated bytes and syncs
it and the root directory, selected copy first, then completes a missing or
invalid copy (creation stopped after A) through the A/B store, one generation
above the existing copies, as creation would have. Valid copies are never
re-encoded, so repeated recoveries leave both files unchanged. Read-only
inspection, including the deep check, never writes them.

Unproven final-tail bytes may be truncated after a crash. Intact later records
do not prove the durability of earlier damaged bytes, because unsynced sectors
may persist out of order. A missing/stale advisory mark cannot weaken the v2
proof requirement. Recovered sequence/index bookkeeping also accounts for proof
metadata that can outlive the segment it names.

A failed append can leave bytes beyond the last accepted record. The writer
retains a cleanup flag until truncation and synchronization succeed, including
when the next operation is a shorter write, FLUSH, or segment roll.

After a journal writeback error, a plain fsync retry may leave clean but
unpersisted page-cache bytes behind. The writer re-reads and rewrites its
accepted pending range in 64 KiB chunks, compares an ephemeral streaming
fingerprint, and only then synchronizes it. Recovery similarly binds each
prefix to the bytes accepted by its scan, rewrites and verifies that prefix,
then synchronizes before publishing both required proofs. Changed bytes refuse
recovery or the durability acknowledgement. Normal successful live flushes
avoid this extra rewrite; recovery pays an additional pass over valid data.
While a rewrite is still owed, the engine reports the volume `degraded` and
`journal_writeback_uncertain`, and counts `journal_sync_failures_total`; a
successful barrier clears the flag, a successful checkpoint does not. Proof
publication failure also keeps the barrier pending, including when its retry
has no new append. Data sync alone does not advance the public durable boundary
or make those records checkpoint-eligible. Recovery publishes every accepted
horizon to both proof copies before READY.

Segment scanning uses fixed 64 KiB scratch, and neither volume attach nor the
deep checker retains a payload while validating. Attach scans the accepted
segments a second time and replays their records through a ciphertext batch
with a 1 MiB grouping target (plus at most one record of up to
`max_ciphertext_size`); the deep checker keeps the index of each unit that has
a record above the checkpoint. The four-unit overwrite regression
(`review_r3_recovery_memory.rs`) asserts that 64 MiB of history raises the heap
peak over 1 MiB of history by at most 256 KiB for attach (at most 2 MiB in
all) and by at most 64 KiB for the deep check (at most 512 KiB in all).
Those unit indexes, the record headers both keep as checkpoint evidence (for at
most 65,536 units at a time) and segment/allocation metadata
still consume memory; public all-record APIs retain their return contract. See the
[measurements and limits](durable-recovery.md#cost-and-verification-limits).

The overlay keeps both the latest version and the latest durable version for
each unit. This distinction is required when a newer unflushed write exists at
checkpoint time. The durable boundary can move inside `append` itself: an
automatic segment roll synchronizes the sealed segment and publishes its proof.
The volume promotes the overlay after every journal operation and *before* publishing a newer
version of the same unit; checkpointing re-derives the checkpointable set from
the journal's own boundary rather than trusting earlier promotions.

Checkpointing captures a fixed durable horizon and shared overlay versions under
the volume lock, then releases that lock while writing and synchronizing slot
data. The live overlay remains readable, and new journal writes can proceed,
including writes to the same unit or a new shard. A separate checkpoint gate
serializes this whole sequence. Publication reacquires the volume lock, updates
the current allocation metadata, fsyncs the data directory before clearing any
dirty flag, commits the captured checkpoint horizon, and only then deletes
covered journal segments and retires overlay versions through that horizon.
Newer versions remain pending for a later checkpoint. A checkpoint that fails
part-way retains the journal and incomplete steps needed for retry.

Engine reads, journal writes, FLUSH, checkpoint data/metadata work, recovery in
`Engine::attach`, and free-space queries run on Tokio's blocking pool. Storage
locks are acquired asynchronously before dispatch. A dispatched read or write
keeps its admission charge, and a write keeps its unit locks, until the storage
operation finishes even if its caller is cancelled. Slow storage therefore does
not monopolize a Tokio worker or let a later write overtake an unfinished write
to the same unit. Checkpoint slot writes and shard syncs run outside the exclusive
volume lock; preparation and metadata publication still hold it. Cancelling a
checkpoint caller leaves its owned task running through publication or failure,
so another checkpoint cannot overtake its data writes. Inline journal reclaim
uses the same gate and repeats capacity admission after reclaim. Clean adapter
shutdown also signals and joins the checkpoint worker,
including an already dispatched free-space query, before releasing the volume.
Attach-time key-canary metadata I/O remains synchronous.

Proof replicas share the backing filesystem. Their CRCs do not provide
authenticity or an external freshness anchor against coordinated valid rollback.
Additional proof-file and directory syncs need target-system latency measurement;
the current protocol prioritizes durable evidence over reducing barrier calls.

Slot headers are authoritative; the shard catalog and the allocation maps are
accelerators that an A/B fallback can leave one generation behind. Opening the
store adopts data files the catalog copy does not list and, for a shard with an
invalid or absent allocation copy, audits its slot headers and repairs the map
in memory (the next checkpoint persists it; the deep check reports it). Reading
a cleared slot probes its header before answering zeros. A cataloged shard with
no valid allocation copy at all refuses attach, as does a shard whose data file
is missing while the catalog names it or its allocation map lists a slot.

In debug builds the overlay, journal, and volume verify their invariants after
every mutation (`check_invariants`), so the randomized suites described in
[testing](testing.md) fail at the first accounting slip rather than at a later
symptom.

Checkpoints are not only a shutdown step. A background worker checkpoints when
the journal crosses a size watermark with a sealed segment to delete (the
active segment never is), when backing free space drops below the
checkpoint reserve, and on a time interval, syncing unsynced records first so
each pass applies them. It also checkpoints when the in-memory overlay reaches
half of its byte or unit bound, and as soon as a write is refused for backing
space. The
write path forces a journal sync once unsynced bytes reach their limit, reclaims
inline at the hard journal or overlay limit (other writes queue behind an
inline reclaim,
so the space it frees goes to the write that ran it), and refuses writes with
ENOSPC unless fresh
backing space covers the emergency reserve, configured checkpoint headroom,
projected record bytes, and all segment headers created by that write, or when
the journal or overlay cannot be
reclaimed. A
failed reclaim marks the engine degraded until a later checkpoint succeeds; the
[remediation log](review-remediation.md#bounded-journal) lists the exact rules.

## Provider boundary

Every provider declares plaintext sizes, maximum ciphertext size, batching,
retry safety, integrity, context binding, and a compatibility identity. Maki
validates response count, order, unit index, and size on every call, and
refuses an encrypt result that carries its own plaintext anywhere in it (an
echo alone, behind a nonce, before a tag, or both): an endpoint that
starts passing data through after attach is charged and failed over instead of
having plaintext persisted. A provider self-test runs before attach, and multi-endpoint configurations verify
cross-endpoint ciphertext compatibility.

The self-test proves only that the provider is coherent with itself. The key
canary proves that it is the provider and key the volume was written with: a
fixed, volume-bound plaintext encrypted at a reserved unit index on the first
attach and decrypted back on every later one. The configured provider type and
key name are also compared with the superblock. The non-cryptographic `fake`
provider is compiled in only with the `fake-provider` feature and refused at
configuration validation otherwise.

Remote providers sit behind a batch scheduler: concurrent requests are
coalesced into bounded provider calls (targets, maxima, and a maximum wait from
configuration), whole requests are never split, requests that share a unit go
in separate calls (results are matched by position and unit index, which
cannot tell two versions of one unit apart), and each lane's pending work is
bounded by count and bytes so a slow provider applies backpressure instead of
growing memory. Each lane keeps several batches in flight (bounded by
`limits.max_crypto_inflight_batches`), so one slow batch does not serialize the
requests behind it. Local providers are called directly.

The dispatcher and the random-prefix wrapper check every unit of a call before
the first RPC and refuse the whole call for one they cannot carry. The
scheduler applies the same per-unit checks at admission, request by request,
so a request with such a unit (an empty ciphertext from a damaged slot, say)
fails alone instead of failing every request coalesced with it. It checks
plaintext against the sizes the layer below reports, so that report lists only
what the layer serves: the wrapper its logical unit, and a dispatcher bound to
the volume's provider unit that unit alone, whatever other sizes its endpoints
have in common. Only a
retry-safe provider has a rejected coalesced call re-sent request by request;
a provider that is not retry-safe is never sent a request twice, so its
rejection reaches every request in the call.

Queued groups own their payload and admission charge together. Cancellation
removes the complete group even if it is behind another group waiting for an
RPC slot. An active coalesced RPC remains necessary until its last caller
leaves. For bounded-error calls, one caller budget covers admission, coalescing,
the slot wait, and the provider response; dispatch does not restart it.

Every deadline exit answers the same way: the last error an endpoint returned
before the deadline for the RPC batch in progress (one batch of items with its
retries and failovers), with that error's class, or the deadline error when no
endpoint failed that batch, and one count in
`maki_crypto_deadline_exceeded_total` whatever the error. A call larger than
the endpoints' common batch limit is sent as several RPC batches, one after
another, and reports only the current one, since an earlier batch that has
since succeeded does not explain why the call is late. The dispatcher's own
exits (before the first pass, at the top of a pass, right after a failed RPC,
in admission, with an RPC in flight) share one path. A scheduler caller's
budget starts before queueing, so it usually runs out before the dispatcher's,
while the shared RPC is still running. Each scheduler caller therefore has an
observer, which its queued group carries into the provider call that serves it
(the coalesced batch or a per-request re-send) as a task-local. The dispatcher
records there the latest endpoint error of its RPC batch in progress (without
the not-sent mark), cleared when the next batch starts, and its own deadline
exits. The observer records nothing at or after the caller's deadline, so a
caller that leaves on its own timer returns what the dispatcher had seen before
that deadline, whichever task runs first. A dispatcher hides the observer from
its endpoints, so a nested set reports to the outer set only through its
result: its expiry is a failure of that peer, counted by the nested set and not
as the outer operation's deadline.

The dispatcher validates quarantined endpoints in background tasks, never on
the request path. Only proof that an endpoint serves another contract rejects
it for the life of the set; an inconclusive validation (a failed exchange,
such as a timeout, a truncated reply or a request refused without an
integrity failure) is retried with the circuit breaker's
doubling open interval, and the endpoint serves only after a validation
succeeds in full. Each admitted call owns a circuit-breaker permit for its
generation. Completion, operation deadline, cancellation, request/provider
errors, and retry-budget refusal all release a HalfOpen probe slot; outcomes
that are not endpoint failures do not advance the failure count. A stale
permit cannot affect a later breaker generation. Abandoning an RPC also
releases its transport inflight slot.

The HTTP transport never follows a redirect (a 3xx fails the endpoint over
rather than re-sending plaintext to a server-chosen URL) and never uses a proxy
from the environment (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY` are ignored), so
plaintext only goes to the configured endpoint. It removes request
URLs from transport errors before classification and formatting, keeping query
credentials out of those error messages. Its connector, hyper-util's as for
gRPC, gives each address of a family a fixed share of the request `timeout`
(reqwest's `connect_timeout`, which hyper-util divides among them), so an
address that does not answer leaves the next one time. reqwest builds that
connector and keeps hyper-util's 300 ms before the other family, which the
provider cannot change without a connector of its own
([remote HTTP mapping](configuration.md#remote-http-mapping)); a `timeout`
under 600 ms is accepted with a warning. The gRPC provider builds the same
connector itself and sets that delay to `min(300 ms, timeout / 2)`. The
WebSocket transport resolves the endpoint's host itself and connects straight
to its addresses. Its other address family starts 300 ms after the first, or
halfway to the deadline when less than 600 ms are left when the dial begins
(the gRPC connector's delay is half of its whole `timeout`, fixed when the
provider is built, and the HTTP one's stays at 300 ms). Each family's
addresses but the last share out what is left of the request's attempt
deadline and the last has the rest, where the connector gives every address a
fixed share, and the last failure is reported, where the connector keeps a
family's first. TLS (verified for the URL's host)
and the upgrade run on the first connection made, and the other attempt is
dropped. Each WebSocket connection generation
owns both reader and writer futures in one task. Timeout, request cancellation,
connection replacement, and provider drop retire that generation, cancel its
task, release its socket, and fail its pending requests without disturbing a
successor connection.

All remote transports support verified TLS and optional client certificate
authentication. They trust one set of roots, built by `maki_crypto::tls_trust`:
the host's trust store, the public roots compiled into the binary and the
configured `ca_file` ([configuration](configuration.md#providers)). WSS and
gRPC configuration resolves client keys through the same credential router as
HTTP. Explicit TLS settings cannot be applied to a plaintext endpoint, and
certificate failures never downgrade the connection.

Provider errors are classified as throttled, retryable, endpoint-fatal,
request-fatal, or provider-fatal. Only eligible failures enter bounded full-
jitter retry. A response that breaks the provider contract (malformed body,
wrong item count, bad encoding) and an HTTP 404/405/410 are charged to the
endpoint that sent them: its breaker counts the failure and a retry-safe
request fails over to another endpoint, so a misrouted endpoint cannot absorb
most traffic. An operation is never sent again to an endpoint that broke the
contract for it. The violation is reported at once only when every validated
endpoint has broken the contract for that operation (a single endpoint
included; quarantined endpoints do not count). While another validated
endpoint remains, even one that failed transiently or whose circuit is
cooling, the operation stays in the normal backoff loop whatever order the
endpoints were tried in: under `stall` it stays pending, and under
`bounded-error` it ends at `max_operation_time`. Retry budgets, circuit
breakers, endpoint limits, and global byte and request semaphores prevent a
failing provider from causing unbounded work.

A provider that is not retry-safe is sent each request at most once: after an
attempt that may have reached the endpoint fails, the dispatcher neither
retries nor fails over, under either availability policy. An attempt that
provably never left Maki does not count. Transports mark such an error as not
sent (`CryptoError::not_sent`, which keeps its class and breaker charge) only
where they can prove that no request byte was written: HTTP for reqwest
connect errors (TCP connect or TLS handshake), gRPC for failures and timeouts
before the request is handed to tonic on an established connection, and
WebSocket for failures before the request frame reaches an upgraded
connection (TCP, TLS, the upgrade, the send queue or the attempt timeout).
The dispatcher fails such a request over and, under the availability policy,
retries it like a request not yet sent. The mark describes the whole call: it
is dropped once any attempt, an earlier chunk of the dispatch, an earlier
per-item HTTP request, or an earlier transparent WebSocket reconnect attempt
may have sent the request.

## Cache and growth

The optional cache stores plaintext under `(unit_index, write_sequence)`. A
version mismatch is always a miss, so correctness does not depend on invalidation
timing. A slow reader's older version never displaces a newer cached one:
neither its `put` nor its lookup evicts the newer entry. A partial-unit write
takes the unit's current plaintext from the cache the same way, so a small
write over a cached unit needs no payload read or decryption. Entries use zeroizing buffers and are never written back. A read
establishes the current sequence first (overlay entry or 64-byte slot header)
and serves a hit without reading the payload or calling the provider, so the
cache saves both the ciphertext read and the crypto call; the trade-off
(payload damage under a valid header is served until eviction) is described
with the [read-cache settings](configuration.md#read-cache).

The virtual device capacity is fixed by the volume geometry. Maki creates
backing shards lazily as writes reach new regions. Filesystem-level growth is a
separate privileged `lvextend` and `xfs_growfs` operation.

## Security boundaries

- The nbdkit data plane runs as the `maki` user with no Linux capabilities.
- The plugin advertises configured NBD block sizes and validates request
  length, range, and alignment before copying write plaintext into Maki or
  submitting work to the engine.
- The control socket exposes status, metrics, checkpoint, drain, and reload
  only.
- Socket creation keeps the process umask unchanged. A private staging
  directory hides the socket until its group and mode are set; rename then
  publishes the ready socket at its configured path.
- Its default path is `/run/maki-control/<volume>/control.sock`; the packaged
  runtime layout lets `maki-admin` reach it through a separate directory tree
  while keeping the NBD runtime tree restricted to the daemon's group.
- Privileged storage operations are isolated in `maki-attach`.
- Keys and plaintext must not be logged. `SecretBuffer` owners are redacted
  and zeroized; remote serialization also creates allocations with separate
  lifetimes. See [transport memory protection](transport-memory.md) for the
  verified ownership boundaries and remaining copies.
- Optional buffer page locks have shared ownership: buffers on the same page
  keep it locked until the final owner releases it. Drop zeroizes before
  releasing ownership; `into_vec` transfers zeroization to the caller and
  releases only that buffer's lock ownership.
- Configuration rejects literal values for sensitive headers.
- Every loader reads a volume configuration through one checked reader
  (`maki_nbdkit::config_file`): on Unix a final symlink, a second hard link, an
  owner other than root or the loading process's user, or group or other write
  access refuses the file before it is parsed
  ([configuration file](configuration.md#configuration-file)).
- Repeated credential names must declare the same source throughout a volume
  configuration; conflicting sources are rejected before credentials load.
- A malformed provider response is treated as a contract failure, never trusted.
- Default v2/v3 backings do not provide historical rollback protection:
  restoring an older, internally valid whole image or an older valid
  ciphertext for the same unit is not detected. An experimental
  [rollback-protected backing](rollback-protection.md) is available for new
  Linux volumes; it anchors an authenticated copy-on-write store in an
  independently managed local witness filesystem or a remote witness service
  (TLS 1.3 mutual authentication, monotonic fencing, administrator restore
  epochs, optional etcd quorum). Both modes are experimental and not
  campaign-qualified; the Merkle-tree manifest from the
  [design proposal](rollback-protection-design.md) remains unimplemented.
  [Status](status.md) records the current state of both.

See [Configuration](configuration.md), [Operations](operations.md), and the
[technical specification](../SPEC.md) for detailed contracts.
