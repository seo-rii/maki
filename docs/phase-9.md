# Phase 9 — WebSocket and gRPC

Status: **complete** (all SPEC §51 cases green; every transport passes the shared conformance suite)

## WebSocket (`maki-crypto-websocket`)

One JSON object per text frame: `{"id", "op", "profile", "volume", "items":[{"unit","data"}]}` → `{"id", "items":[{"data"}]}` or `{"id", "error":{"class","message"}}`.

- **Correlation IDs**: monotonic `id` per request, registered *before* send so a fast response can never look stale. A background reader resolves pending requests by id — **out-of-order responses** go to the right caller (tested with a server that answers request pairs in reverse).
- **Stale responses**: frames with unknown ids (from earlier connection generations, or bogus) are logged and dropped, never delivered (SPEC §29-adjacent stale-read prevention at the transport level).
- **Reconnection**: on connection loss every pending request fails `Retryable`, the dead connection is discarded, and the next call transparently reconnects (one in-call retry). Tested with a server that closes after the first response — the second call succeeds over a new connection.
- **Frame-size limits** both ways: outgoing requests over `max_frame_bytes` are `NonRetryableRequest` before send; incoming oversized frames kill the connection (tungstenite cap) and surface as retryable.
- Server error objects map to the SPEC §31 classes.

## gRPC (`maki-crypto-grpc`)

Native tonic/prost implementation with hand-written message types (no protoc build dependency): `CryptoBatchRequest{volume_id, compatibility_id, items[{unit_index, data}]}` → `CryptoBatchResponse{items}`. The reference contract is `packaging/examples/maki-crypto.proto`.

- **Configurable paths + metadata**: method paths (`/pkg.Service/Method`) and ascii metadata (resolved credentials) are per-volume configuration; metadata is validated at construction (bad values fail closed). Tested against a hand-rolled tonic service requiring an `authorization` token.
- **Status mapping** (SPEC §31): ResourceExhausted→Throttled; Unavailable/DeadlineExceeded/Aborted/Internal→Retryable; Unauthenticated/PermissionDenied→EndpointFatal; InvalidArgument/NotFound/OutOfRange/FailedPrecondition→NonRetryableRequest; Unimplemented→ProviderFatal. Verified both by table and over the wire.
- **Reorder detection**: responses echo `unit_index`; a reordering server is caught as a `Contract` error.
- **Message-size limits**: client-side pre-check plus tonic encode/decode caps.
- **Dynamic descriptor** loading (arbitrary vendor message shapes via reflection) is deferred to milestone M7 per SPEC §58; the fixed contract above is the supported surface for now, giving vendors a stable shape at any service name.

## Shared conformance suite (SPEC §51 "Every transport MUST pass the same provider conformance suite")

`maki_crypto::selftest::provider_conformance` = the Phase-2 self-test (capabilities coherence, pattern round trips, order/size validation, tamper detection when integrity is claimed) + a wide distinctive-content batch + a repeated-encryption statelessness check. Now passed by: **local GCM-SIV, local XTS, HTTP, WebSocket, gRPC** (each wired into its phase test file).

## Notes

- Both transports are `CryptoProvider`s, so they compose with `CheckedProvider`, the Phase-5 `EndpointSet` (retry/budget/breaker/failover), and the attach self-test unchanged.

## Daemon wiring (follow-up, `maki-nbdkit/tests/phase9_daemon.rs`)

`provider = "remote-websocket"` / `"remote-grpc"` assemble through the same dispatcher as `remote-http` (shared `dispatch_endpoint_set`: cross-endpoint self-test, retry/budget/breaker/failover):

- `[crypto.websocket]`: `[[endpoint]]` (ws:// URLs), `timeout`, `max_frame_bytes`.
- `[crypto.grpc]`: `[[endpoint]]` (http:// URLs), `timeout`, `max_message_bytes`, `encrypt_path`/`decrypt_path` (default: the reference contract `/maki.CryptoService/{Encrypt,Decrypt}Batch`), and `[crypto.grpc.metadata]` — ascii metadata where sensitive keys (authorization etc.) must be credential references (SPEC §9, validated in `maki-format`), resolved through the daemon's key router.
- **TLS gap, fail closed**: neither transport build compiles in TLS yet, so `wss://`/`https://` endpoints or a `[crypto.*.tls]` section refuse attach with an explicit error — never a silent downgrade. Use `remote-http` (full rustls, mTLS, custom CA) where TLS is required; wiring TLS into ws/grpc is a follow-up (tungstenite `rustls-tls` / tonic `tls` features).
