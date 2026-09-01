# Phase 2 — CryptoProvider

Status: **complete** (all SPEC §44 test-first cases green)

## What was built

### `maki-crypto` additions
- **`CheckedProvider`** (`checked.rs`) — caller-side contract enforcement. Maki never trusts a provider's batch result shape: count, order, `unit_index` match, non-empty ciphertext, and `max_ciphertext_size` are validated on every call. Violations are `CryptoError::Contract` (ProviderFatal class — a misbehaving provider is never retried into). The reusable validators (`validate_encrypt_result`/`validate_decrypt_result`) are also used by the self-test.
- **Provider self-test** (`selftest.rs`) — run before attach (feeds SPEC §27 recovery step "run provider self-test"): capability coherence (compat ID vs volume, plaintext size support), round trip of zeros/0xFF/pseudo-random patterns, batch-order verification, size limits, and — when integrity is claimed — active tamper detection (a provider that *claims* integrity but accepts tampered ciphertext is rejected as ProviderFatal).
- **`cross_endpoint_self_test`** — SPEC §34: A→B and B→A encrypt/decrypt with plaintext comparison; same-key endpoints pass, different-key endpoints fail even with matching compatibility IDs.

### `maki-crypto-local`
- **`AesGcmSivProvider`** — AES-256-GCM-SIV; ciphertext = `nonce[12] ‖ ct ‖ tag[16]` (28-byte overhead). AAD binds volume UUID, crypto unit index, format version, compatibility ID (SPEC §17) — relocated/replayed-elsewhere ciphertext fails authentication. Capabilities: integrity **Verified**, context-binding **Verified**.
- **`AesXtsProvider`** — AES-256-XTS via `xts-mode`; tweak = unit index; length-preserving. **Documented as providing no authenticated integrity** (SPEC §17): capabilities report integrity/context-binding **Absent**, so the engine relies on slot CRCs and never assumes tamper detection.
- **Key sources** (`keysource.rs`) — `KeySource` trait with `FileKeySource` (systemd `$CREDENTIALS_DIRECTORY` / root-only secret dir; raw or hex file contents; credential names validated against path traversal), `EnvKeySource` (dev only), `MapKeySource` (tests), and `systemd_credential_source()`. Missing/short keys **fail closed** with `ProviderFatal` (feeds PRIV-014).

## SPEC §44 test-first cases → tests

| Case | Test |
|---|---|
| round trip | `gcm_siv_round_trip`, `xts_round_trip`, `well_behaved_provider_passes_checked_wrapper` |
| randomized ciphertext | `gcm_siv_rejects_corrupt_and_random_ciphertext` |
| maximum-size violation | `oversize_ciphertext_is_rejected` |
| batch reorder | `batch_reorder_is_rejected` |
| missing item | `missing_item_is_rejected` |
| duplicate item | `duplicate_item_is_rejected` (+ `mismatched_index_is_rejected`) |
| compatibility mismatch | `self_test_detects_compatibility_mismatch`, provider-level context checks |
| cross-endpoint decrypt | `cross_endpoint_self_test_requires_interchangeable_ciphertext`, `cross_endpoint_same_key_passes_different_key_fails` |
| local AEAD context binding | `gcm_siv_binds_unit_index_volume_and_profile` |
| secret logging leakage | `secrets_never_appear_in_debug_output`, `error_messages_never_contain_plaintext_or_key` |

Plus key handling: `wrong_key_length_fails_closed`, `file_key_source_reads_raw_and_hex`, `different_key_cannot_decrypt`.

## Decisions of record

- GCM-SIV nonces are random per encryption and carried in the ciphertext; SIV's misuse resistance makes accidental repetition non-catastrophic. Overhead is 28 bytes ⇒ with 4096-byte units, `max_ciphertext_size = 4124` fits the SPEC's 4384 contract with margin.
- AEAD failure messages carry zero data ("AEAD authentication failed") — corrupted ciphertext yields an error, never plaintext, and errors never leak key/plaintext bytes.
- XTS `context_binding` is reported Absent even though the tweak encodes position: an unverifiable property is treated as absent (SPEC §16).
