//! Opt-in random padding before plaintext reaches an underlying provider.

use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use rand::{rngs::OsRng, TryRngCore};
use zeroize::Zeroize;

use crate::{
    checked::CheckedProvider, BatchCapability, CiphertextUnit, ContextField, CryptoCapabilities,
    CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
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
            inner: CheckedProvider::pinned(inner, wire_unit_size),
            inner_compatibility_id: inner_caps.crypto_compatibility_id,
            logical_unit_size,
            wire_unit_size,
            prefix_bytes,
            caps,
            max_operation_time,
        })
    }

    fn inner_context(&self, context: &CryptoContext) -> Result<CryptoContext, CryptoError> {
        if context.crypto_compatibility_id != self.caps.crypto_compatibility_id {
            return Err(CryptoError::UnsupportedContext(
                ContextField::CompatibilityId,
            ));
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

        let mut expanded = Vec::new();
        expanded.try_reserve_exact(items.len()).map_err(|_| {
            CryptoError::ProviderFatal("failed to allocate expanded plaintext batch".into())
        })?;
        for item in items {
            let mut data = SecretBuffer::zeroed(self.wire_unit_size as usize);
            OsRng
                .try_fill_bytes(&mut data.expose_mut()[..self.prefix_bytes as usize])
                .map_err(|_| {
                    CryptoError::ProviderFatal("operating-system random source failed".into())
                })?;
            data.expose_mut()[self.prefix_bytes as usize..].copy_from_slice(item.data.expose());
            expanded.push(PlaintextUnit {
                unit_index: item.unit_index,
                data,
            });
        }
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
        let expanded = self.inner.decrypt_batch(&inner_context, items).await?;
        let mut stripped = Vec::new();
        stripped.try_reserve_exact(expanded.len()).map_err(|_| {
            CryptoError::ProviderFatal("failed to allocate decrypted plaintext batch".into())
        })?;
        for item in expanded {
            let payload = &item.data.expose()[self.prefix_bytes as usize..];
            let mut data =
                SecretBuffer::with_capacity(self.logical_unit_size as usize).map_err(|_| {
                    CryptoError::ProviderFatal("failed to allocate decrypted plaintext unit".into())
                })?;
            data.try_extend_from_slice(payload).map_err(|_| {
                CryptoError::ProviderFatal("decrypted plaintext capacity invariant failed".into())
            })?;
            stripped.push(PlaintextUnit {
                unit_index: item.unit_index,
                data,
            });
        }
        Ok(stripped)
    }
}
