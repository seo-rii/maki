# Remote crypto buffer lifetime

`SecretBuffer` erases its allocation before releasing its optional page lock.
Remote serialization can create other representations of the same plaintext.
The `secure-buffers` setting covers registered buffers, and does not prove that
every transport allocation is locked or erased. Logical request budgets also
do not measure total resident memory.

## WebSocket decoded responses

Base64 output is decoded directly into an exactly sized `SecretBuffer`, with
the guard installed before any plaintext is written. Invalid base64 erases
partially decoded output. If a later response item has a wrong unit, missing
data, or invalid encoding, the earlier decoded items are also erased.
Successful decryption transfers these guards to the caller without copying;
encryption transfers the known ciphertext into ordinary output vectors.

The JSON/base64 strings, parsed JSON values and WebSocket frame/library
buffers are separate allocations. Their complete lifetime is not protected by
this decoded-output change. MAKI-015 and the total-memory work in MAKI-032
remain open.

The `decoded_response_tests` unit suite observes initialized allocations
immediately before deallocation, including partial decoder output and a later
item failure. It also checks canonical padding, exact output lengths, invalid
alphabet and trailing bits. These tests do not inspect freed memory or claim
to observe library-private copies. The complete WebSocket package passed
28 tests and all-targets strict Clippy on 2026-09-12; exact logs are recorded
in the [readiness review](production-readiness-review-2026-09-08.md).

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
