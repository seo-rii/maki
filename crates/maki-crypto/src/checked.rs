//! Caller-side provider-contract enforcement (SPEC §44).
//!
//! Maki never trusts a provider's batch result shape. `CheckedProvider`
//! wraps any provider and verifies count, order, unit indices, and size
//! limits on every call; a violation is `CryptoError::Contract`
//! (ProviderFatal). It is never retried against the endpoint that sent it; in
//! an `EndpointSet` it charges that endpoint's breaker, and a retry-safe
//! request fails over to an endpoint it has not tried yet (R5-005).

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::OnceCell;
use zeroize::Zeroize;

use crate::error::CryptoError;
use crate::provider::CryptoProvider;
use crate::types::{CiphertextUnit, CryptoCapabilities, CryptoContext, PlaintextUnit};

pub struct CheckedProvider {
    inner: Arc<dyn CryptoProvider>,
    caps: OnceCell<CryptoCapabilities>,
    /// The volume's unit size when known: every decrypted plaintext must
    /// be exactly this long, not merely a size the provider supports.
    unit_size: Option<u32>,
}

impl CheckedProvider {
    pub fn new(inner: Arc<dyn CryptoProvider>) -> Self {
        Self {
            inner,
            caps: OnceCell::new(),
            unit_size: None,
        }
    }

    /// A checked provider that also pins decrypt results to `unit_size`
    /// (C-08): a provider declaring several plaintext sizes could otherwise
    /// return a shorter or longer unit that the engine would slice out of
    /// range or silently re-encrypt at the wrong length.
    pub fn pinned(inner: Arc<dyn CryptoProvider>, unit_size: u32) -> Self {
        Self {
            inner,
            caps: OnceCell::new(),
            unit_size: Some(unit_size),
        }
    }

    async fn caps(&self) -> Result<&CryptoCapabilities, CryptoError> {
        self.caps
            .get_or_try_init(|| self.inner.capabilities())
            .await
    }
}

/// An encrypt response is untrusted until the entire batch passes validation.
/// In particular, its purported ciphertext may still contain plaintext. Own all
/// returned buffers through validation, including earlier and extra items.
struct PendingEncryptResult(Vec<CiphertextUnit>);

impl Drop for PendingEncryptResult {
    fn drop(&mut self) {
        for unit in &mut self.0 {
            // Vec::zeroize also erases spare capacity: a provider may have
            // shortened its buffer after writing sensitive bytes into it.
            unit.data.zeroize();
        }
    }
}

/// Validate an owned encrypt response, erasing every payload on rejection.
/// Successful validation transfers the existing allocations without copying.
pub(crate) fn validate_owned_encrypt_result(
    items: &[PlaintextUnit],
    out: Vec<CiphertextUnit>,
    caps: &CryptoCapabilities,
) -> Result<Vec<CiphertextUnit>, CryptoError> {
    let mut pending = PendingEncryptResult(out);
    validate_encrypt_result(items, &pending.0, caps)?;
    Ok(std::mem::take(&mut pending.0))
}

/// Validate an encrypt result against its inputs and the provider contract.
/// This borrowed checker does not own or erase buffers. Internal response
/// owners use `validate_owned_encrypt_result` to guard rejection paths.
pub fn validate_encrypt_result(
    items: &[PlaintextUnit],
    out: &[CiphertextUnit],
    caps: &CryptoCapabilities,
) -> Result<(), CryptoError> {
    if out.len() != items.len() {
        return Err(CryptoError::Contract(format!(
            "encrypt returned {} results for {} items",
            out.len(),
            items.len()
        )));
    }
    for (i, (item, ct)) in items.iter().zip(out.iter()).enumerate() {
        if ct.unit_index != item.unit_index {
            return Err(CryptoError::Contract(format!(
                "encrypt result {i} has unit_index {} but item has {}",
                ct.unit_index, item.unit_index
            )));
        }
        if ct.data.is_empty() {
            return Err(CryptoError::Contract(format!(
                "encrypt result {i} is empty"
            )));
        }
        if ct.data.len() > caps.max_ciphertext_size as usize {
            return Err(CryptoError::Contract(format!(
                "encrypt result {i} is {} bytes, exceeding max_ciphertext_size {}",
                ct.data.len(),
                caps.max_ciphertext_size
            )));
        }
        // A pass-through answer would be persisted as "ciphertext". Checked on
        // every call, not only by the attach self-test: an endpoint can start
        // echoing later (a stub backend behind a load balancer), and framing
        // (a nonce before it, a tag after it, or both, as an integrity-only
        // profile produces) must not hide the echo (BUG-105). A real cipher
        // reproduces a whole unit of plaintext with negligible probability.
        // The error charges the endpoint that answered.
        let plain = item.data.expose();
        if !plain.is_empty() && contains_plaintext(&ct.data, plain, |a, b| a == b) {
            return Err(CryptoError::Contract(format!(
                "encrypt result {i} carries its plaintext: the provider is not encrypting"
            )));
        }
    }
    Ok(())
}

/// Validate a decrypt result against its inputs and the provider contract.
pub fn validate_decrypt_result(
    items: &[CiphertextUnit],
    out: &[PlaintextUnit],
    caps: &CryptoCapabilities,
) -> Result<(), CryptoError> {
    if out.len() != items.len() {
        return Err(CryptoError::Contract(format!(
            "decrypt returned {} results for {} items",
            out.len(),
            items.len()
        )));
    }
    for (i, (item, pt)) in items.iter().zip(out.iter()).enumerate() {
        if pt.unit_index != item.unit_index {
            return Err(CryptoError::Contract(format!(
                "decrypt result {i} has unit_index {} but item has {}",
                pt.unit_index, item.unit_index
            )));
        }
        if !caps.accepts_plaintext_size(pt.data.len()) {
            return Err(CryptoError::Contract(format!(
                "decrypt result {i} has unsupported plaintext size {}",
                pt.data.len()
            )));
        }
    }
    Ok(())
}

#[async_trait]
impl CryptoProvider for CheckedProvider {
    fn max_operation_time(&self) -> Option<std::time::Duration> {
        self.inner.max_operation_time()
    }

    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.caps().await?.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let caps = self.caps().await?.clone();
        let out = self.inner.encrypt_batch(context, items).await?;
        validate_owned_encrypt_result(items, out, &caps)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let caps = self.caps().await?.clone();
        let out = self.inner.decrypt_batch(context, items).await?;
        validate_decrypt_result(items, &out, &caps)?;
        if let Some(unit_size) = self.unit_size {
            if let Some(pt) = out.iter().find(|pt| pt.data.len() != unit_size as usize) {
                return Err(CryptoError::Contract(format!(
                    "decrypt of unit {} returned {} bytes, volume unit size is {unit_size}",
                    pt.unit_index,
                    pt.data.len()
                )));
            }
        }
        Ok(out)
    }
}

// Keep byte comparisons injectable so adversarial-work regressions measure
// the algorithm's actual work without depending on clocks or CPU speed.
fn contains_plaintext(
    haystack: &[u8],
    needle: &[u8],
    mut equal: impl FnMut(u8, u8) -> bool,
) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > haystack.len() {
        return false;
    }
    // KMP retains the longest matched prefix instead of comparing it again
    // at every candidate offset. Preprocessing and scanning are both linear,
    // including long repeated prefixes and periodic near matches.
    let mut prefix = vec![0; needle.len()];
    let mut matched = 0;
    for index in 1..needle.len() {
        loop {
            if equal(needle[index], needle[matched]) {
                matched += 1;
                break;
            }
            if matched == 0 {
                break;
            }
            matched = prefix[matched - 1];
        }
        prefix[index] = matched;
    }
    matched = 0;
    for byte in haystack {
        loop {
            if equal(*byte, needle[matched]) {
                matched += 1;
                if matched == needle.len() {
                    return true;
                }
                break;
            }
            if matched == 0 {
                break;
            }
            matched = prefix[matched - 1];
        }
    }
    false
}

#[cfg(test)]
mod substring_tests {
    use super::contains_plaintext;

    #[test]
    fn f03_search_matches_slice_windows_exhaustively() {
        for haystack_length in 0..=8 {
            for bits in 0..1usize << haystack_length {
                let haystack: Vec<_> = (0..haystack_length)
                    .map(|i| ((bits >> i) & 1) as u8)
                    .collect();
                for needle_length in 0..=5 {
                    for bits in 0..1usize << needle_length {
                        let needle: Vec<_> = (0..needle_length)
                            .map(|i| ((bits >> i) & 1) as u8)
                            .collect();
                        let expected = needle.is_empty()
                            || haystack
                                .windows(needle.len())
                                .any(|window| window == needle);
                        assert_eq!(
                            contains_plaintext(&haystack, &needle, |a, b| a == b),
                            expected
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn f03_repeated_prefix_near_matches_have_linear_comparison_cost() {
        for length in [64, 256, 1024] {
            let haystack = vec![b'a'; length * 8];
            let mut needle = vec![b'a'; length];
            needle[length - 1] = b'b';
            let mut comparisons = 0;
            assert!(!contains_plaintext(&haystack, &needle, |a, b| {
                comparisons += 1;
                a == b
            }));
            assert!(
                comparisons <= 4 * (haystack.len() + needle.len()),
                "{comparisons} comparisons for needle length {length}"
            );
        }
    }

    #[test]
    fn f03_periodic_near_matches_have_linear_comparison_cost() {
        let haystack: Vec<_> = b"abab".iter().copied().cycle().take(8192).collect();
        let mut needle: Vec<_> = b"abab".iter().copied().cycle().take(1024).collect();
        needle[1023] = b'c';
        let mut comparisons = 0;
        assert!(!contains_plaintext(&haystack, &needle, |a, b| {
            comparisons += 1;
            a == b
        }));
        assert!(
            comparisons <= 4 * (haystack.len() + needle.len()),
            "{comparisons} comparisons"
        );
    }
}
