# Remote crypto buffer lifetime

`SecretBuffer` erases its allocation before releasing its optional page lock.
Remote serialization can create other representations of the same plaintext.
The `secure-buffers` setting covers registered buffers, and does not prove that
every transport allocation is locked or erased. Logical request budgets also
do not measure total resident memory.

## HTTP decoded payloads

HTTP response payloads are decoded into an exactly sized
`SecretBuffer`. The guard exists before the first Base64, Base64URL, or
hex byte is written, and the fixed allocation cannot reallocate while decoding.
A malformed symbol therefore erases partial output before returning the error;
successful extraction moves the same guard into the provider result. Dropping a
partly built batch also erases payloads decoded before a later item fails.
After a per-item or batch JSON response has been parsed into its owned guarded
tree, the original guarded HTTP body is dropped before payload decoding starts.
This shortens the overlap between the wire representation and decoded outputs;
the tree still holds its encoded strings until extraction finishes.

Focused allocation regressions observe the selected output immediately before
deallocation and show that malformed Base64 and hex inputs no longer release a
partial plaintext prefix. Response growth allocates a new guarded owner, copies
into it, wipes the replaced owner, then swaps. Request JSON trees remain under a
drop guard until serialization; recursive cleanup drains and wipes object keys
and values, including pointer replacement and construction errors. The complete
HTTP package passed 46 tests with three ignored network tests, and the changed
packages passed scoped all-targets strict Clippy on 2026-09-13.

HTTP request hex encoding preallocates its complete output and writes digits
directly, without per-byte formatted strings or growing the output allocation.
The request-tree guard wipes the resulting string after serialization or an
error. This removes transient hex allocations that the guard could not reach;
it does not page-lock the request tree or change the public encoder's `String`
ownership. Allocation regressions require only the final allocation to exist
for nonempty hex input and no allocations for empty input, with no intermediate
deallocations. Wire checks cover both cases and every byte value.

Resolved header and query values are erased when their operation specification
is dropped. Header values are guarded while the specification is assembled, so
a later mapping error also erases values already resolved. Credential bytes are
validated as UTF-8 by borrowing the key-source buffer rather than copying it to
an intermediate vector. The combined mTLS certificate/private-key PEM is
guarded during construction and erased when its TLS specification is dropped,
including construction and client-builder errors.

Maki-owned payloads, serialized request bodies, streamed response buffers and
decoded outputs use page-lock-capable `SecretBuffer`s. Fixed-capacity allocation
locks the whole allocation before plaintext is appended, when locking is
enabled and succeeds. Response growth acquires a new guarded allocation before
copying, then erases and releases the old owner. `Bytes::from_owner` retains the
request-body guard until the last HTTP body clone is released. Raw decryption
responses transfer their owner directly to the caller.

Response JSON is deserialized directly into a guarded tree. Every completed
string and object key is copied into a `SecretBuffer` allocated before its
first byte is written, with page locking when enabled and successful. Both
per-item and batched responses use that tree. Dropping an incomplete object or
array after a syntax error erases its completed strings and keys; duplicate
values and discarded duplicate keys are erased as they are replaced. The tree
also owns cleanup after success, response-contract errors and unwinding, rather
than relying on a wipe after parsing completes. JSON pointer lookup, duplicate
last-value-wins behavior, number validation and recursion limits are unchanged.

Request JSON trees, credential-value strings and combined identity PEMs still
have zeroizing ownership without per-allocation page locks. Plain source
configuration strings and copies made inside reqwest, hyper or the kernel
remain separate owners. The pinned parser and TLS patches described below
extend erasure to their application-data heap buffers, including unfinished
escaped strings rejected before the visitor sees them. Admission does not
account for simultaneous decoded, encoded and library copies. MAKI-015 and
the total-memory
work in MAKI-032 therefore remain open.

The 2026-10-07 response-tree regressions first observed unzeroized deallocation
of completed strings in malformed JSON and of duplicate keys and values through
the real per-item response parser. They now require those allocations to be
erased, together with successful response trees and a batch's earlier decoded
payloads when a later item fails. Focused checks cover response key/value page
locks, JSON pointer compatibility, malformed UTF-8 and recursion limits.

The 2026-09-20 follow-up passed the complete `maki-crypto` and
`maki-crypto-http` suites (175 passing invocations, two ignored) and strict
all-target Clippy. Linux page-lifetime tests verify that spare-capacity pages
remain locked, that shared-page owners retain their locks, and that memory is
erased before deallocation. Evidence:
`~/logs/maki-http-memory-20260920T084013Z/` (`exit.status` 0).

## WebSocket requests

Request serialization borrows input units and streams base64 and JSON directly
into fixed `SecretBuffer` storage. It does not create the former intermediate
request JSON tree or owned base64 strings. A counting pass uses the same
serializer to enforce the frame limit, checked arithmetic and addressable
buffer capacity before allocating the output. A second pass cannot grow the
buffer; partial errors erase anything already written.

The encoded allocation remains owned through the WebSocket message queue and
`Bytes`/`Message` clones. Its last owner erases the buffer before releasing its
optional page lock. Cancellation before connecting also drops the owner. The
existing wire order, escaping and payload encoding are preserved.

This protects Maki's owned request storage. Stack serializer/base64 scratch and
tungstenite's internal output/framing copies are outside this guarantee.
Incoming response ownership is described below. The final request unit passed all
35 WebSocket package tests and strict Clippy on 2026-09-12, including actual
request cancellation, rejection before output allocation, partial writer
failure, exact wire compatibility and final clone ownership.

## WebSocket decoded responses

Base64 output is decoded directly into an exactly sized `SecretBuffer`, with
the guard installed before any plaintext is written. Invalid base64 erases
partially decoded output. If a later response item has a wrong unit, missing
data, or invalid encoding, the earlier decoded items are also erased.
Successful decryption transfers these guards to the caller without copying;
encryption transfers the known ciphertext into ordinary output vectors.

The decoded-output guard is separate from the incoming JSON and frame owners
described below. Library-private copies remain outside both guarantees.
MAKI-015 and the total-memory work in MAKI-032 remain open.

The `decoded_response_tests` unit suite observes initialized allocations
immediately before deallocation, including partial decoder output and a later
item failure. It also checks canonical padding, exact output lengths, invalid
alphabet and trailing bits. These tests do not inspect freed memory or claim
to observe library-private copies. The complete WebSocket package passed
28 tests and all-targets strict Clippy on 2026-09-12; exact logs are recorded
in the [readiness review](qualification/historical-reviews/production-readiness-review-2026-09-08.md).

## WebSocket incoming responses

The reader takes ownership of the received message payload before validating
UTF-8. When `Bytes` proves the allocation unique, it transfers that allocation
into `SecretBuffer`; otherwise it copies into an already guarded buffer without
modifying the shared source. Invalid UTF-8 therefore also drops the owned
guard. Frames rejected inside tungstenite before reaching the reader remain
outside this protection.

The private response tree stores every owned JSON string and object key in
`SecretBuffer`, including base64 data, error text and unknown nested fields.
Borrowed strings copy directly into guarded storage; owned strings transfer
their allocation. Dropping malformed partial trees, overwritten duplicate
values, stale responses or responses to cancelled receivers erases these
owners. Debug output is redacted. Ordinary object lookups still select the
last duplicate value. Negative self-test errors retain their stricter known
field uniqueness and type checks without a second parse or remote strings
in type-error messages. JSON syntax, recursion and frame limits are unchanged.

Allocation tests inspect initialized bytes immediately before deallocation,
including unique sliced payloads whose original prefix and suffix become
spare capacity. Drop erases the adopted vector's full capacity. Optional page
locking covers the entire allocation, including pages of spare capacity.
Shared source owners and tungstenite read/framing buffers retain
library-controlled lifetimes. The pinned parser patch separately erases its
private escape-decoding scratch. The response
tree's container/number storage and many small values also remain outside any
total resident-memory bound. These changes do not close MAKI-015 or MAKI-032.

The incoming-response unit adds 14 focused regressions. The complete
WebSocket package passed 49 tests and all-targets strict Clippy on 2026-09-12.

## gRPC provider-owned messages

The provider uses private protobuf items backed by `SecretBuffer` that erase
their full data capacity on Drop, `Message::clear`, and replacement of the
singular bytes field. The
replacement path erases the old allocation before validating or reserving
space for new data, and copies directly from the decoder input. Each child
owns this protection even when decoding fails before it joins its parent.

Request size rejection, response count/unit rejection, and cancellation also
drop these owners. Successful decryption transfers the allocation into
`SecretBuffer` without copying; successful encryption transfers ciphertext
to the caller. Private Debug output redacts bytes. Public `CryptoItem`,
`CryptoBatchRequest`, and `CryptoBatchResponse` retain their existing API and
wire encoding; external callers using those public structs are responsible
for their own allocation lifetime.

The private item is page-lock-capable before its first decoded byte is written,
and retains that owner through rejection, cancellation and successful transfer.
Tonic's encoded/decoded buffers and HTTP framing buffers remain separate
allocations. The pinned TLS patch separately erases rustls-owned plaintext.
These changes do not establish complete transport zeroization, page locking, or
a total resident-memory cap.

Fourteen focused regressions cover full-capacity deallocation, duplicate and
malformed fields, partial nested decoding, public wire compatibility, actual
tonic encoding and cancellation before encoding or while awaiting trailers,
and real loopback RPC rejection/success. The complete gRPC package passed
31 tests and all-targets strict Clippy on 2026-09-12.

The 2026-09-20 page-lock ownership follow-up passed all 32 gRPC package tests
and strict all-target Clippy in isolation from the separate TLS feature.
Evidence: `~/logs/maki-grpc-memory-20260920T085835Z/` (`exit.status` 0).

## Local providers and key material

The local providers produce plaintext only inside guarded buffers (R4-002).
`local-aes-gcm-siv` copies the ciphertext body into a `SecretBuffer` that is
page-locked (when enabled) *before* decryption and decrypts it in place with
the detached-tag AEAD API; on an authentication failure the cipher re-encrypts
the buffer and the buffer is zeroized when dropped. Encryption copies the
caller's plaintext into a guarded working buffer and encrypts in place, so no
unlocked copy of the plaintext exists at any point. `local-aes-xts` follows
the same pattern. The earlier implementation used the allocating AEAD API,
which decrypted into an ordinary vector and wrapped it afterwards.

Key files (`file`, systemd `credential`) are read directly into a guarded
buffer and hex-decoded into another; `env` keys are copied out of the
environment string, which is then erased (the environment block itself is
outside the daemon's control and is a development-only source).
`maki_crypto::secret::unguarded_wraps()` counts buffers that were wrapped
after the fact; `review_r4_guarded_buffers.rs` requires it to stay constant
through encryption, decryption and key loading.

The cipher objects holding the expanded AES key schedules (`Aes256GcmSiv`,
the XTS pair of `Aes256` instances) live in a `maki_crypto::SecretBox`: a heap
allocation that is page-locked under `secure-buffers` before the cipher is
moved into it and stays locked until the cipher has been dropped, which
zeroizes the schedule (the AES crate's `zeroize` feature). The box also erases
the staging copy the move leaves behind. Lock failures are counted with every
other `SecretBuffer` failure. `AesGcmSivProvider::key_schedule_locked()` and
`AesXtsProvider::key_schedule_locked()` report the state;
`key_schedules_are_page_locked_under_secure_buffers` requires it.

**Residual.** Temporaries the cipher crates create on the stack while
expanding the key, and stack or register state during encryption, are outside
the page-lock claim; `memory_lock_mode = "all"` (`mlockall`) or the
secure-swap policy covers them.

## Parser and TLS library-owned copies

Maki pins local patches of `serde_json` 1.0.151 and `rustls` 0.23.45 through
workspace dependency overrides. All HTTP and WebSocket JSON parsing, and all
rustls-based HTTP, WebSocket and gRPC TLS connections resolve to these patched
sources. The [vendor guide](../vendor/README.md) records the covered owners and
upgrade procedure. Published archive checksums record the original sources;
source inventories, patch hashes, resolved dependency paths and permitted
parser features are checked in
CI; silently replacing a patch or resolving a second library version fails the
contract.

The JSON parser's escaped-string scratch, reader scratch, integer128 scanning
and formatted error-message heap buffers erase removed bytes before reuse.
Growth creates a guarded replacement before copying and wipes the old full
allocation before release. Drop also wipes the full capacity, including an
unfinished escape that never reaches a visitor. Valid JSON escapes, Unicode
surrogates, duplicate keys, error text and locations retain upstream behavior.
The optional `raw_value`, `arbitrary_precision` and `float_roundtrip` paths are
refused at compile time until their additional owners have been reviewed;
Maki's resolved default/std parser configuration does not use them.

The convenience `from_slice`/`from_str` functions drop their parser before
returning. A caller that keeps a `Deserializer` alive retains its latest
scratch until reuse or Drop; a visitor can borrow that scratch during parsing.

TLS plaintext queues erase consumed bytes immediately and wipe their complete
allocations when replaced or dropped. Deframer compaction erases obsolete tails;
growth and shrink copy into a replacement and erase the retired allocation.
Encryption staging and owned record payloads retain guards through errors and
unwinding. Inbound borrowed payloads erase data on decryption errors, and
truncation or range extraction erases excluded bytes. Successful transfers to
API callers retain the caller's buffer ownership. These changes apply to both
the ring and aws-lc providers without changing their cryptographic algorithms.

Allocation regressions observe initialized storage immediately before release,
and inspect still-live tails after consumption/reuse. The observer initializes
spare capacity and never reads freed storage. Existing upstream JSON and TLS
unit tests and Maki's local HTTPS/WSS/gRPC TLS and mTLS tests provide protocol
compatibility checks. This is local evidence, not a new external campaign.

This covers library-owned application-data heap copies in these two patches.
It does not establish complete process-wide plaintext erasure: hyper/h2,
tungstenite and tonic keep their own reusable framing allocations; shared
source buffers and caller-owned parsed values or output remain independent.
Parser/crypto stack and registers, kernel buffers, and process termination
that skips destructors also remain outside normal heap-owner cleanup. No
production global allocator is installed. Wiping only on allocator release
would miss stale plaintext in live reused framing buffers. These patches do
not page-lock library buffers or establish a total resident-memory cap, so
MAKI-015 and the total-memory work in MAKI-032 remain open.

## Further copy reduction options

The HTTP hex and response-lifetime changes above remove avoidable allocations
and shorten ownership without changing the wire contract. The remaining options,
in implementation priority order, are not yet implemented:

| Priority | Option | Benefit and cost |
|---|---|---|
| 1 | Adopt uniquely owned HTTP response chunks | Apply the WebSocket frame pattern to `reqwest::Response::chunk()` output: if `Bytes::try_into_mut` succeeds, move the allocation into a `SecretBuffer` before copying or rejecting it. This can erase a received chunk's complete capacity. Shared source allocations must remain untouched. The change is small but needs unique, sliced, shared and size-limit error ownership tests. |
| 2 | Serialize HTTP requests from borrowed payloads | Use the WebSocket serializer's counting pass and fixed guarded output, eliminating the intermediate base64/hex `String` and request `Value` tree. This is a moderate change because HTTP supports dynamic JSON pointer mappings and replacement semantics. Preserve exact wire output, mapping errors, batch order and cancellation cleanup. |
| 3 | Shorten WebSocket frame ownership | Release the original guarded frame immediately after its fully owned response tree has been parsed, as HTTP now does. This reduces overlap during response routing but leaves framing ownership unchanged. |

The daemon already uses `Engine::read_secret` through nbdkit's `pread`; replacing
the convenience `Engine::read` API is not needed for that path. The final copy
into nbdkit's caller-owned output remains outside `SecretBuffer` ownership.
Likewise, framing and tonic allocations cannot all be erased by changes to
provider-owned buffers or the two library patches. Process memory locking,
core-dump suppression and the
secure-swap policy mitigate disk exposure of residual copies; they do not erase
those copies or establish a total memory bound. Using `memory_lock_mode = "all"`
requires an adequate `LimitMEMLOCK` and measured peak memory, so it is a deployment
choice rather than a substitute for reducing copies.
