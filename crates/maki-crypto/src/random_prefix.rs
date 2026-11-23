//! Opt-in random padding before plaintext reaches an underlying provider.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use rand::{rngs::OsRng, TryRngCore};
use zeroize::Zeroize;

use crate::{
    checked::CheckedProvider, provider::private::SelfTestCaller, BatchCapability, CiphertextUnit,
    CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};

/// Prepends fresh random bytes to every plaintext unit before encryption and
/// removes them only after underlying decryption (and authentication when the
/// provider supplies it) plus full response validation.
pub struct RandomPrefixProvider {
    inner: CheckedProvider,
    inner_compatibility_id: String,
    logical_unit_size: u32,
    wire_unit_size: u32,
    prefix_bytes: u32,
    caps: CryptoCapabilities,
    max_operation_time: Option<Duration>,
}

impl RandomPrefixProvider {
    pub async fn new(
        inner: Arc<dyn CryptoProvider>,
        logical_unit_size: u32,
        prefix_bytes: u32,
        compatibility_id: String,
    ) -> Result<Self, CryptoError> {
        if logical_unit_size == 0 {
            return Err(CryptoError::ProviderFatal(
                "logical unit size must be nonzero".into(),
            ));
        }
        if compatibility_id.is_empty() {
            return Err(CryptoError::ProviderFatal(
                "random-prefix compatibility id must not be empty".into(),
            ));
        }
        if !(16..=256).contains(&prefix_bytes) || !prefix_bytes.is_multiple_of(16) {
            return Err(CryptoError::ProviderFatal(
                "random prefix size must be a multiple of 16 between 16 and 256 bytes".into(),
            ));
        }
        let wire_unit_size = logical_unit_size.checked_add(prefix_bytes).ok_or_else(|| {
            CryptoError::ProviderFatal("logical unit plus random prefix overflows u32".into())
        })?;
        let inner = CheckedProvider::pinned(inner, wire_unit_size);
        let inner_caps = inner.capabilities().await?;
        if !inner_caps
            .supported_plaintext_sizes
            .contains(&wire_unit_size)
        {
            return Err(CryptoError::ProviderFatal(format!(
                "inner provider does not accept expanded plaintext size {wire_unit_size}"
            )));
        }
        if inner_caps.max_ciphertext_size < wire_unit_size {
            return Err(CryptoError::ProviderFatal(
                "inner maximum ciphertext size is smaller than expanded plaintext size".into(),
            ));
        }
        if compatibility_id == inner_caps.crypto_compatibility_id {
            return Err(CryptoError::ProviderFatal(
                "random-prefix compatibility id must differ from the inner profile".into(),
            ));
        }
        if inner_caps.batch.max_items == 0 {
            return Err(CryptoError::ProviderFatal(
                "inner batch item limit must be nonzero".into(),
            ));
        }
        let byte_items = inner_caps.batch.max_bytes / u64::from(wire_unit_size);
        let declared_items = if inner_caps.batch.supported {
            u64::from(inner_caps.batch.max_items)
        } else {
            1
        };
        let max_items = byte_items.min(declared_items);
        if max_items == 0 {
            return Err(CryptoError::ProviderFatal(
                "inner batch limits cannot carry one expanded plaintext unit".into(),
            ));
        }
        let max_items = u32::try_from(max_items).map_err(|_| {
            CryptoError::ProviderFatal("effective inner batch item limit exceeds u32".into())
        })?;
        let caps = CryptoCapabilities {
            provider_id: inner_caps.provider_id.clone(),
            crypto_compatibility_id: compatibility_id,
            supported_plaintext_sizes: vec![logical_unit_size],
            max_ciphertext_size: inner_caps.max_ciphertext_size,
            stateless: inner_caps.stateless,
            retry_safe: inner_caps.retry_safe,
            batch: BatchCapability {
                supported: inner_caps.batch.supported,
                max_items,
                max_bytes: u64::from(max_items) * u64::from(logical_unit_size),
            },
            integrity: inner_caps.integrity,
            context_binding: inner_caps.context_binding,
            replay_protection: inner_caps.replay_protection,
        };
        let max_operation_time = inner.max_operation_time();
        Ok(Self {
            inner,
            inner_compatibility_id: inner_caps.crypto_compatibility_id,
            logical_unit_size,
            wire_unit_size,
            prefix_bytes,
            caps,
            max_operation_time,
        })
    }

    fn inner_context(&self, context: &CryptoContext) -> Result<CryptoContext, CryptoError> {
        // The wrapper translates the compatibility id; it does not bind it.
        // Its refusal of another id is therefore not the field evidence a
        // provider's `UnsupportedContext` is. The self-test's probe of the id
        // is forwarded to the inner provider (`decrypt_compatibility_probe`);
        // one that reaches this check as an ordinary decrypt fails closed.
        if context.crypto_compatibility_id != self.caps.crypto_compatibility_id {
            return Err(CryptoError::ProviderFatal(format!(
                "random-prefix provider serves compatibility id {:?}, not {:?}",
                self.caps.crypto_compatibility_id, context.crypto_compatibility_id
            )));
        }
        let mut translated = context.clone();
        translated.crypto_compatibility_id = self.inner_compatibility_id.clone();
        Ok(translated)
    }

    fn validate_batch(&self, count: usize, bytes: u64) -> Result<(), CryptoError> {
        if count > self.caps.batch.max_items as usize || bytes > self.caps.batch.max_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "batch of {count} items and {bytes} plaintext bytes exceeds random-prefix provider limits"
            )));
        }
        Ok(())
    }

    /// Decrypt under `context`, or, for the self-test's compatibility-id
    /// probe (`probe`), under the inner provider's foreign id: the probe
    /// passes the same checks, is sent with the translated inner context,
    /// and its result is validated before the prefix is removed.
    async fn decrypt_units(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
        probe: Option<SelfTestCaller>,
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let inner_context = self.inner_context(context)?;
        let bytes = u64::try_from(items.len())
            .ok()
            .and_then(|count| count.checked_mul(u64::from(self.logical_unit_size)))
            .ok_or_else(|| {
                CryptoError::NonRetryableRequest("ciphertext batch size overflows".into())
            })?;
        self.validate_batch(items.len(), bytes)?;
        if let Some(item) = items.iter().find(|item| {
            item.data.is_empty() || item.data.len() > self.caps.max_ciphertext_size as usize
        }) {
            return Err(CryptoError::NonRetryableRequest(format!(
                "unit {} has invalid ciphertext size {} (maximum {})",
                item.unit_index,
                item.data.len(),
                self.caps.max_ciphertext_size
            )));
        }
        let mut units = match probe {
            None => self.inner.decrypt_batch(&inner_context, items).await?,
            Some(caller) => {
                self.inner
                    .decrypt_compatibility_probe(caller, &inner_context, items)
                    .await?
            }
        };
        for item in &mut units {
            // The checked provider has pinned each expanded unit to the wire
            // size. Keep its guarded allocation and erase the vacated tail.
            item.data
                .expose_mut()
                .copy_within(self.prefix_bytes as usize.., 0);
            item.data.truncate(self.logical_unit_size as usize);
        }
        Ok(units)
    }
}

fn expand_units(
    items: &[PlaintextUnit],
    wire_size: usize,
    prefix_len: usize,
    mut fill: impl FnMut(&mut [u8]) -> Result<(), CryptoError>,
) -> Result<Vec<PlaintextUnit>, CryptoError> {
    let mut expanded = Vec::new();
    expanded.try_reserve_exact(items.len()).map_err(|_| {
        CryptoError::ProviderFatal("failed to allocate expanded plaintext batch".into())
    })?;
    for item in items {
        let mut data = SecretBuffer::zeroed(wire_size);
        data.expose_mut()[prefix_len..].copy_from_slice(item.data.expose());
        expanded.push(PlaintextUnit {
            unit_index: item.unit_index,
            data,
        });
    }
    match expanded.as_mut_slice() {
        [] => {}
        [unit] => fill(&mut unit.data.expose_mut()[..prefix_len])?,
        units => {
            // Limit temporary locked memory even when the provider accepts
            // large batches. Each prefix consumes a disjoint slice of fresh entropy.
            const MAX_ENTROPY_BYTES: usize = 16 * 1024;
            let chunk_units = MAX_ENTROPY_BYTES / prefix_len;
            let mut entropy = SecretBuffer::zeroed(units.len().min(chunk_units) * prefix_len);
            for chunk in units.chunks_mut(chunk_units) {
                let bytes = &mut entropy.expose_mut()[..chunk.len() * prefix_len];
                fill(bytes)?;
                for (unit, prefix) in chunk.iter_mut().zip(bytes.chunks_exact(prefix_len)) {
                    unit.data.expose_mut()[..prefix_len].copy_from_slice(prefix);
                }
            }
        }
    }
    Ok(expanded)
}

#[async_trait]
impl CryptoProvider for RandomPrefixProvider {
    fn max_operation_time(&self) -> Option<Duration> {
        self.max_operation_time
    }

    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.caps.clone())
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        let inner_context = self.inner_context(context)?;
        let bytes = u64::try_from(items.len())
            .ok()
            .and_then(|count| count.checked_mul(u64::from(self.logical_unit_size)))
            .ok_or_else(|| {
                CryptoError::NonRetryableRequest("plaintext batch size overflows".into())
            })?;
        self.validate_batch(items.len(), bytes)?;
        if let Some(item) = items
            .iter()
            .find(|item| item.data.len() != self.logical_unit_size as usize)
        {
            return Err(CryptoError::NonRetryableRequest(format!(
                "unit {} has plaintext size {}, expected {}",
                item.unit_index,
                item.data.len(),
                self.logical_unit_size
            )));
        }

        let expanded = expand_units(
            items,
            self.wire_unit_size as usize,
            self.prefix_bytes as usize,
            |bytes| {
                OsRng.try_fill_bytes(bytes).map_err(|_| {
                    CryptoError::ProviderFatal("operating-system random source failed".into())
                })
            },
        )?;
        let mut encrypted = self.inner.encrypt_batch(&inner_context, &expanded).await?;
        if expanded
            .iter()
            .zip(&encrypted)
            .any(|(plain, cipher)| plain.data.expose() == cipher.data)
        {
            // A no-op provider would otherwise evade the outer self-test because
            // prefix || logical plaintext differs from the caller's logical unit.
            // Scrub any unchanged plaintext returned in the ciphertext buffers.
            for item in &mut encrypted {
                item.data.zeroize();
            }
            return Err(CryptoError::ProviderFatal(
                "ciphertext equals expanded plaintext: the inner provider is not encrypting".into(),
            ));
        }
        Ok(encrypted)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.decrypt_units(context, items, None).await
    }

    async fn decrypt_compatibility_probe(
        &self,
        caller: SelfTestCaller,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        // `context` is the volume's own (derived) context: the probe asks the
        // inner provider about the base id it actually receives, exactly as
        // the same provider is probed on a volume without a prefix.
        self.decrypt_units(context, items, Some(caller)).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefixes_request_entropy_in_bounded_batches() {
        for (count, prefix_len, requests) in [
            (0, 16, vec![]),
            (1, 16, vec![16]),
            (64, 16, vec![1024]),
            (65, 256, vec![16384, 256]),
        ] {
            let items: Vec<_> = (0..count)
                .map(|index| PlaintextUnit {
                    unit_index: index,
                    data: SecretBuffer::from_slice(&index.to_le_bytes()),
                })
                .collect();
            let mut sizes = Vec::new();
            let mut sequence = 0_u8;
            let expanded = expand_units(&items, prefix_len + 8, prefix_len, |bytes| {
                sizes.push(bytes.len());
                for prefix in bytes.chunks_exact_mut(prefix_len) {
                    prefix.fill(sequence);
                    sequence += 1;
                }
                Ok(())
            })
            .unwrap();
            assert_eq!(sizes, requests);
            assert_eq!(expanded.len(), items.len());
            for (index, unit) in expanded.iter().enumerate() {
                assert_eq!(unit.unit_index, items[index].unit_index);
                let (prefix, payload) = unit.data.expose().split_at(prefix_len);
                assert!(prefix.iter().all(|byte| *byte == index as u8));
                assert_eq!(payload, items[index].data.expose());
            }
        }
    }

    #[test]
    fn a_later_entropy_failure_discards_the_batch() {
        let items: Vec<_> = (0..65)
            .map(|unit_index| PlaintextUnit {
                unit_index,
                data: SecretBuffer::zeroed(1),
            })
            .collect();
        let mut requests = 0;
        let result = expand_units(&items, 257, 256, |bytes| {
            requests += 1;
            if requests == 2 {
                return Err(CryptoError::ProviderFatal("entropy unavailable".into()));
            }
            bytes.fill(42);
            Ok(())
        });
        assert_eq!(requests, 2);
        assert!(
            matches!(result, Err(CryptoError::ProviderFatal(message)) if message == "entropy unavailable")
        );
    }
}
