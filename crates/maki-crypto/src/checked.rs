//! Caller-side provider-contract enforcement (SPEC §44).
//!
//! Maki never trusts a provider's batch result shape. `CheckedProvider`
//! wraps any provider and verifies count, order, unit indices, and size
//! limits on every call; a violation is `CryptoError::Contract`
//! (ProviderFatal — a misbehaving provider is never retried into).

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::OnceCell;

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

/// Validate an encrypt result against its inputs and the provider contract.
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
        validate_encrypt_result(items, &out, &caps)?;
        Ok(out)
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
