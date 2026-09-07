//! Provider self-test, run before a volume attaches (SPEC §27, §34, §44).

use crate::checked::{validate_decrypt_result, validate_encrypt_result};
use crate::error::{CryptoError, ErrorClass};
use crate::provider::CryptoProvider;
use crate::types::{CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit};
use crate::SecretBuffer;

/// Consecutive sub-ranges of `items`, each within the provider's batch limits
/// (`max_items` items and `max_bytes` by `size`), always at least one item.
/// The self-test must respect a provider's advertised limits — a single-item
/// or small-batch provider is still valid — so it splits its fixed patterns
/// into admissible RPCs rather than sending one oversized batch the provider
/// then rejects (MAKI-010).
fn batch_ranges<T>(
    items: &[T],
    caps: &CryptoCapabilities,
    size: impl Fn(&T) -> u64,
) -> Vec<std::ops::Range<usize>> {
    let max_items = caps.batch.max_items.max(1) as usize;
    let max_bytes = caps.batch.max_bytes.max(1);
    let mut ranges = Vec::new();
    let mut start = 0;
    while start < items.len() {
        let mut end = start;
        let mut bytes = 0u64;
        while end < items.len() {
            let next = bytes.saturating_add(size(&items[end]));
            // Keep at least one item per batch even if it alone exceeds the
            // byte budget (the provider's own oversize handling applies then).
            if end > start && (end - start + 1 > max_items || next > max_bytes) {
                break;
            }
            bytes = next;
            end += 1;
            if end - start >= max_items {
                break;
            }
        }
        ranges.push(start..end);
        start = end;
    }
    ranges
}

/// Encrypt `items` in capability-respecting batches, validating each batch's
/// shape, preserving order (MAKI-010).
async fn encrypt_chunked(
    provider: &dyn CryptoProvider,
    context: &CryptoContext,
    items: &[PlaintextUnit],
    caps: &CryptoCapabilities,
) -> Result<Vec<CiphertextUnit>, CryptoError> {
    let mut out = Vec::with_capacity(items.len());
    for range in batch_ranges(items, caps, |p| p.data.len() as u64) {
        let chunk = &items[range];
        let cts = provider.encrypt_batch(context, chunk).await?;
        validate_encrypt_result(chunk, &cts, caps)?;
        out.extend(cts);
    }
    Ok(out)
}

/// Decrypt `items` in capability-respecting batches, validating each batch's
/// shape, preserving order (MAKI-010).
async fn decrypt_chunked(
    provider: &dyn CryptoProvider,
    context: &CryptoContext,
    items: &[CiphertextUnit],
    caps: &CryptoCapabilities,
) -> Result<Vec<PlaintextUnit>, CryptoError> {
    let mut out = Vec::with_capacity(items.len());
    for range in batch_ranges(items, caps, |c| c.data.len() as u64) {
        let chunk = &items[range];
        let pts = provider.decrypt_batch(context, chunk).await?;
        validate_decrypt_result(chunk, &pts, caps)?;
        out.extend(pts);
    }
    Ok(out)
}

fn patterns(unit_size: usize) -> Vec<PlaintextUnit> {
    let mut pseudo = vec![0u8; unit_size];
    let mut x: u32 = 0x2545_F491;
    for b in pseudo.iter_mut() {
        // xorshift — deterministic, not secret
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = x as u8;
    }
    vec![
        PlaintextUnit {
            unit_index: 0,
            data: SecretBuffer::from_vec(vec![0x00; unit_size]),
        },
        PlaintextUnit {
            unit_index: 1,
            data: SecretBuffer::from_vec(vec![0xFF; unit_size]),
        },
        PlaintextUnit {
            unit_index: 2,
            data: SecretBuffer::from_vec(pseudo),
        },
    ]
}

/// Full pre-attach self-test of one provider:
/// capability coherence, round trip, batch order, size limits, and (when
/// integrity is claimed) tamper detection.
pub async fn provider_self_test(
    provider: &dyn CryptoProvider,
    context: &CryptoContext,
    unit_size: usize,
    expected_compatibility_id: &str,
) -> Result<(), CryptoError> {
    let caps = provider.capabilities().await?;

    if caps.crypto_compatibility_id != expected_compatibility_id {
        return Err(CryptoError::ProviderFatal(format!(
            "crypto compatibility mismatch: provider reports {:?}, volume requires {:?} — attach refused",
            caps.crypto_compatibility_id, expected_compatibility_id
        )));
    }
    if context.crypto_compatibility_id != expected_compatibility_id {
        return Err(CryptoError::ProviderFatal(
            "volume context compatibility id does not match configuration".to_string(),
        ));
    }
    if !caps.accepts_plaintext_size(unit_size) {
        return Err(CryptoError::ProviderFatal(format!(
            "provider does not support plaintext size {unit_size}"
        )));
    }
    let items = patterns(unit_size);
    let cts = encrypt_chunked(provider, context, &items, &caps).await?;
    let pts = decrypt_chunked(provider, context, &cts, &caps).await?;
    for (orig, got) in items.iter().zip(pts.iter()) {
        if orig.data != got.data {
            return Err(CryptoError::ProviderFatal(
                "self-test round trip mismatch".to_string(),
            ));
        }
    }

    // A provider in pass-through mode (debug/no-op endpoint, a response
    // mapping that echoes the request) round-trips perfectly; attaching it
    // would persist plaintext. Ciphertext must never equal its plaintext
    // (C-09).
    if cts
        .iter()
        .zip(items.iter())
        .any(|(ct, pt)| ct.data == pt.data.expose())
    {
        return Err(CryptoError::ProviderFatal(
            "ciphertext equals plaintext: the provider is not encrypting".to_string(),
        ));
    }

    // A claimed context binding is exercised, not trusted: the same
    // ciphertext presented under another unit index must not decrypt to the
    // same plaintext. Different plaintext (a non-authenticated cipher rebinds
    // by tweak) or a *definitive* rejection are both fine — but a transport
    // error (a provider that times out or drops the connection only on the
    // moved request) proves nothing and must not be read as verification
    // (MAKI-011).
    if caps.context_binding.present() {
        let mut moved = cts[0].clone();
        moved.unit_index = cts[0].unit_index.wrapping_add(1);
        match provider.decrypt_batch(context, &[moved]).await {
            Ok(pts) => {
                if pts
                    .first()
                    .map(|p| p.data == items[0].data)
                    .unwrap_or(false)
                {
                    return Err(CryptoError::ProviderFatal(
                        "provider claims context binding but decrypts under a different unit index"
                            .to_string(),
                    ));
                }
            }
            Err(e) if e.class() == ErrorClass::NonRetryableRequest => {}
            Err(e) => {
                return Err(CryptoError::ProviderFatal(format!(
                    "context-binding self-test inconclusive: the moved ciphertext failed with a \
                     {:?}-class error, not a definitive rejection — attach refused",
                    e.class()
                )));
            }
        }
    }

    // Tamper detection: a flipped ciphertext byte must be rejected with a
    // *definitive* integrity/bad-ciphertext error. Accepting it is fatal; a
    // transport/retryable error (a provider that only ever times out on the
    // tampered request) leaves integrity unproven, so the self-test refuses
    // rather than passing on it (MAKI-011).
    if caps.integrity.present() {
        let mut tampered: Vec<CiphertextUnit> = vec![cts[2].clone()];
        let mid = tampered[0].data.len() / 2;
        tampered[0].data[mid] ^= 0x01;
        match provider.decrypt_batch(context, &tampered).await {
            Ok(_) => {
                return Err(CryptoError::ProviderFatal(
                    "provider claims integrity but accepted tampered ciphertext".to_string(),
                ))
            }
            Err(e) if e.class() == ErrorClass::NonRetryableRequest => {}
            Err(e) => {
                return Err(CryptoError::ProviderFatal(format!(
                    "integrity self-test inconclusive: tampered ciphertext was rejected with a \
                     {:?}-class error, not a definitive integrity failure — attach refused",
                    e.class()
                )))
            }
        }
    }

    Ok(())
}

/// Transport-agnostic provider conformance suite (SPEC §51): every
/// transport (local, HTTP, WebSocket, gRPC) must pass identically.
pub async fn provider_conformance(
    provider: &dyn CryptoProvider,
    context: &CryptoContext,
    unit_size: usize,
    expected_compatibility_id: &str,
) -> Result<(), CryptoError> {
    // Core self-test: capabilities, round trips, order, size, tamper.
    provider_self_test(provider, context, unit_size, expected_compatibility_id).await?;

    // Wider batch with distinctive per-unit content, split into
    // capability-respecting RPCs (MAKI-010).
    let caps = provider.capabilities().await?;
    let n = 32usize;
    let items: Vec<PlaintextUnit> = (0..n)
        .map(|i| PlaintextUnit {
            unit_index: 1000 + i as u64,
            data: SecretBuffer::from_vec(vec![i as u8 ^ 0x5A; unit_size]),
        })
        .collect();
    let cts = encrypt_chunked(provider, context, &items, &caps).await?;
    let pts = decrypt_chunked(provider, context, &cts, &caps).await?;
    for (orig, got) in items.iter().zip(pts.iter()) {
        if orig.data != got.data {
            return Err(CryptoError::ProviderFatal(
                "conformance: wide-batch round trip mismatch".to_string(),
            ));
        }
    }

    // Statelessness sanity: encrypting the same unit twice must decrypt
    // identically both times.
    let again = provider
        .encrypt_batch(
            context,
            &[PlaintextUnit {
                unit_index: 1000,
                data: items[0].data.duplicate(),
            }],
        )
        .await?;
    let back = provider.decrypt_batch(context, &again).await?;
    if back[0].data != items[0].data {
        return Err(CryptoError::ProviderFatal(
            "conformance: repeated encryption round trip mismatch".to_string(),
        ));
    }
    Ok(())
}

/// Cross-endpoint interchangeability (SPEC §34): ciphertext encrypted by A
/// must decrypt on B and vice versa. Run for every endpoint pair before
/// attach.
pub async fn cross_endpoint_self_test(
    a: &dyn CryptoProvider,
    b: &dyn CryptoProvider,
    context: &CryptoContext,
    unit_size: usize,
) -> Result<(), CryptoError> {
    let caps_a = a.capabilities().await?;
    let caps_b = b.capabilities().await?;
    if caps_a.crypto_compatibility_id != caps_b.crypto_compatibility_id {
        return Err(CryptoError::ProviderFatal(format!(
            "endpoints report different compatibility ids: {:?} vs {:?}",
            caps_a.crypto_compatibility_id, caps_b.crypto_compatibility_id
        )));
    }

    for (enc, caps_enc, dec, caps_dec, dir) in [
        (a, &caps_a, b, &caps_b, "A→B"),
        (b, &caps_b, a, &caps_a, "B→A"),
    ] {
        let items = patterns(unit_size);
        // Both sides split into capability-respecting RPCs so a small-batch
        // endpoint is not spuriously rejected (MAKI-010).
        let cts = encrypt_chunked(enc, context, &items, caps_enc).await?;
        let mut pts = Vec::with_capacity(cts.len());
        for range in batch_ranges(&cts, caps_dec, |c| c.data.len() as u64) {
            let chunk = &cts[range];
            let got = dec.decrypt_batch(context, chunk).await.map_err(|e| {
                // A transport-level failure is not proof of incompatibility —
                // preserve its class so the caller can distinguish "down" from
                // "not interchangeable".
                if e.is_retryable() || matches!(e.class(), ErrorClass::EndpointFatal) {
                    e
                } else {
                    CryptoError::ProviderFatal(format!(
                        "cross-endpoint decrypt {dir} failed: {e} — endpoints are not interchangeable"
                    ))
                }
            })?;
            validate_decrypt_result(chunk, &got, caps_dec)?;
            pts.extend(got);
        }
        for (orig, got) in items.iter().zip(pts.iter()) {
            if orig.data != got.data {
                return Err(CryptoError::ProviderFatal(format!(
                    "cross-endpoint round trip {dir} produced different plaintext"
                )));
            }
        }
    }
    Ok(())
}
