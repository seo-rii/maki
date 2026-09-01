//! Provider self-test, run before a volume attaches (SPEC §27, §34, §44).

use crate::checked::{validate_decrypt_result, validate_encrypt_result};
use crate::error::CryptoError;
use crate::provider::CryptoProvider;
use crate::types::{CiphertextUnit, CryptoContext, PlaintextUnit};
use crate::SecretBuffer;

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
    let cts = provider.encrypt_batch(context, &items).await?;
    validate_encrypt_result(&items, &cts, &caps)?;

    let pts = provider.decrypt_batch(context, &cts).await?;
    validate_decrypt_result(&cts, &pts, &caps)?;
    for (orig, got) in items.iter().zip(pts.iter()) {
        if orig.data != got.data {
            return Err(CryptoError::ProviderFatal(
                "self-test round trip mismatch".to_string(),
            ));
        }
    }

    if caps.integrity.present() {
        let mut tampered: Vec<CiphertextUnit> = vec![cts[2].clone()];
        let mid = tampered[0].data.len() / 2;
        tampered[0].data[mid] ^= 0x01;
        if provider.decrypt_batch(context, &tampered).await.is_ok() {
            return Err(CryptoError::ProviderFatal(
                "provider claims integrity but accepted tampered ciphertext".to_string(),
            ));
        }
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

    for (enc, dec, dir) in [(a, b, "A→B"), (b, a, "B→A")] {
        let items = patterns(unit_size);
        let cts = enc.encrypt_batch(context, &items).await?;
        let pts = dec.decrypt_batch(context, &cts).await.map_err(|e| {
            // A transport-level failure is not proof of incompatibility —
            // preserve its class so the caller can distinguish "down" from
            // "not interchangeable".
            if e.is_retryable() || matches!(e.class(), crate::ErrorClass::EndpointFatal) {
                e
            } else {
                CryptoError::ProviderFatal(format!(
                    "cross-endpoint decrypt {dir} failed: {e} — endpoints are not interchangeable"
                ))
            }
        })?;
        validate_decrypt_result(&cts, &pts, &caps_b)?;
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
