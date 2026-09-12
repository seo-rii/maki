# Remote crypto buffer lifetime

`SecretBuffer` erases its allocation before releasing its optional page lock.
Remote serialization can create other representations of the same plaintext.
The `secure-buffers` setting covers registered buffers, and does not prove that
every transport allocation is locked or erased. Logical request budgets also
do not measure total resident memory.

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

This protects Maki's owned request storage. Serializer/base64 scratch and
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
in the [readiness review](production-readiness-review-2026-09-08.md).

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
locking covers its exposed byte range, not every page of spare capacity.
Shared source owners, tungstenite read/framing buffers and serde's private
escape-decoding scratch retain library-controlled lifetimes. The response
tree's container/number storage and many small values also remain outside any
total resident-memory bound. These changes do not close MAKI-015 or MAKI-032.

The incoming-response unit adds 14 focused regressions. The complete
WebSocket package passed 49 tests and all-targets strict Clippy on 2026-09-12.

## gRPC provider-owned messages

The provider uses private protobuf items that erase their full data capacity
on Drop, `Message::clear`, and replacement of the singular bytes field. The
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

The private item is a zeroizing vector, not a page-locked `SecretBuffer`
until a successful decrypt transfers it. Tonic's encoded/decoded buffers and
HTTP/TLS buffers remain separate allocations. These changes do not establish
complete transport zeroization, page locking, or a total resident-memory cap.

Fourteen focused regressions cover full-capacity deallocation, duplicate and
malformed fields, partial nested decoding, public wire compatibility, actual
tonic encoding and cancellation before encoding or while awaiting trailers,
and real loopback RPC rejection/success. The complete gRPC package passed
31 tests and all-targets strict Clippy on 2026-09-12.
