# Phase 8 — HTTP Remote Provider

Status: **complete** (fake-HTTP chaos + TLS + cross-endpoint suites green) · Vendor contract suite and 24-hour hardware soak are deployment-time items (runbook below).

## What was built (`maki-crypto-http`)

`HttpCryptoProvider` — a *configured transport contract*, not a cipher (SPEC §1/§18): Maki never interprets the vendor's cryptography.

- **Request mapping** (SPEC §19): JSON bodies built from `pointer → source` mappings (`payload` with base64/base64url/hex-lower/hex-upper encodings, `unit_index`, `volume_id`, `compatibility_id`, `batch_index`), plus `raw` single-item bodies. Headers (literal or credential-resolved), query parameters, method, path.
- **Batch layouts**: one-request-per-item, or a single request with an `items_path` array of per-item objects. Responses mirror it (`items_path`, per-element `data_path`); an optional `item_index_path` echo is validated — reorders and partial responses are `Contract` errors.
- **Classification** (SPEC §31): 429→Throttled, 5xx/408/timeouts/transport→Retryable, 401/403/407→EndpointFatal, other 4xx→NonRetryableRequest, TLS failures (certificate/handshake chain inspection)→EndpointFatal.
- **Response-size limit**: content-length pre-check plus a hard streaming cap.
- **TLS**: custom CA roots, SAN verification (rustls), mTLS client identity — all wired through reqwest/rustls and exercised against an in-process TLS server (rcgen certs): trusted-CA roundtrip, untrusted-CA rejection, SAN-mismatch rejection, mTLS with/without identity.
- **`from_config`**: builds the provider from the validated SPEC §57 schema, resolving credentialed headers through a `KeySource` (with optional `format = "Bearer {}"` templates); declared capabilities honor SPEC §16 (unprovable ⇒ Absent).
- **No payload logging**: verified by capturing all `TRACE`-level logs during a roundtrip and asserting neither plaintext nor ciphertext encodings appear.

## Daemon integration (`maki-nbdkit::daemon`)

`remote-http` now assembles: per-endpoint `HttpCryptoProvider`s → **cross-endpoint interchangeability check** (SPEC §34; transport failures degrade to a warning and are left to the circuit breaker — proven non-interchangeability refuses attach) → `EndpointSet` dispatcher configured from `[crypto.retry]`, `[crypto.retry_budget]`, `[crypto.circuit_breaker]`, `[limits]`, with `stall`/`bounded-error` mapped to unlimited/bounded passes. Header credentials route systemd-credentials-dir → env (dev fallback).

End-to-end chaos tests drive the *full engine* through the HTTP provider: roundtrip, transient-503 ride-through (including during the attach self-test), and dead-endpoint failover under load.

## SPEC §50 case coverage

raw payload ✓ · JSON mapping ✓ · base64/hex ✓ · headers/query/credentials ✓ · batch reorder ✓ · partial response ✓ · response-size limit ✓ · TLS CA/SAN/mTLS ✓ · 429/503/timeout ✓ · body-mapping self-test ✓ (Phase-2 `provider_self_test` through the real transport) · absence of payload logging ✓ · truncated response ✓.

## Remaining gate items (deployment runbook)

- **Vendor contract suite**: run `provider_self_test` + the phase-8 test corpus against the real vendor endpoint using the production TOML (a `maki check --provider` style invocation of the same code paths).
- **24-hour hardware-provider soak**: `maki-benchmark <config> --duration 24h` against the vendor endpoint; watch `maki_crypto_retries_total`, `maki_circuit_state`, RSS.
