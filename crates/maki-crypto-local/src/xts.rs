//! AES-256-XTS provider (SPEC §17).
//!
//! **No authenticated integrity** (SPEC §17 requires this be documented):
//! XTS is length-preserving and unauthenticated. A modified ciphertext
//! decrypts to garbage *without an error from this provider*; corruption
//! detection relies entirely on the volume layer's slot CRC, and the
//! capability report says `integrity: Absent` so the engine treats it that
//! way. The tweak is the crypto unit index, which binds position but is not
//! verifiable at decrypt time (`context_binding: Absent`).

use aes::cipher::KeyInit;
use aes::Aes256;
use async_trait::async_trait;
use xts_mode::{get_tweak_default, Xts128};

use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};

use crate::keysource::KeySource;

pub struct AesXtsProvider {
    xts: Xts128<Aes256>,
    unit_size: u32,
    compatibility_id: String,
    key_name: String,
}

impl std::fmt::Debug for AesXtsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesXtsProvider")
            .field("unit_size", &self.unit_size)
            .field("compatibility_id", &self.compatibility_id)
            .field("key_name", &self.key_name)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl AesXtsProvider {
    pub fn new(
        keys: &dyn KeySource,
        key_name: &str,
        unit_size: u32,
        compatibility_id: &str,
    ) -> Result<Self, CryptoError> {
        let key = keys.load(key_name)?;
        if key.len() != 64 {
            return Err(CryptoError::ProviderFatal(format!(
                "AES-256-XTS key {key_name:?} has wrong length {} (need 64 bytes)",
                key.len()
            )));
        }
        let (k1, k2) = key.expose().split_at(32);
        let c1 = Aes256::new_from_slice(k1)
            .map_err(|_| CryptoError::ProviderFatal("cipher init failed".to_string()))?;
        let c2 = Aes256::new_from_slice(k2)
            .map_err(|_| CryptoError::ProviderFatal("cipher init failed".to_string()))?;
        if unit_size < 16 {
            return Err(CryptoError::ProviderFatal(
                "XTS requires unit size >= 16".to_string(),
            ));
        }
        Ok(Self {
            xts: Xts128::new(c1, c2),
            unit_size,
            compatibility_id: compatibility_id.to_string(),
            key_name: key_name.to_string(),
        })
    }

    fn check_context(&self, context: &CryptoContext) -> Result<(), CryptoError> {
        if context.crypto_compatibility_id != self.compatibility_id {
            return Err(CryptoError::ProviderFatal(format!(
                "crypto compatibility mismatch: context {:?}, provider {:?}",
                context.crypto_compatibility_id, self.compatibility_id
            )));
        }
        Ok(())
    }
}

#[async_trait]
impl CryptoProvider for AesXtsProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "local-aes-256-xts".to_string(),
            crypto_compatibility_id: self.compatibility_id.clone(),
            supported_plaintext_sizes: vec![self.unit_size],
            max_ciphertext_size: self.unit_size,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 4096,
                max_bytes: 64 << 20,
            },
            integrity: Capability::Absent,
            context_binding: Capability::Absent,
            replay_protection: Capability::Absent,
        })
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.check_context(context)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let pt = item.data.expose();
            if pt.len() != self.unit_size as usize {
                return Err(CryptoError::NonRetryableRequest(format!(
                    "unsupported plaintext size {}",
                    pt.len()
                )));
            }
            let mut buf = pt.to_vec();
            self.xts.encrypt_area(
                &mut buf,
                self.unit_size as usize,
                item.unit_index as u128,
                get_tweak_default,
            );
            out.push(CiphertextUnit {
                unit_index: item.unit_index,
                data: buf,
            });
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.check_context(context)?;
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            if item.data.len() != self.unit_size as usize {
                return Err(CryptoError::Integrity(format!(
                    "XTS ciphertext length {} != unit size {}",
                    item.data.len(),
                    self.unit_size
                )));
            }
            let mut buf = item.data.clone();
            self.xts.decrypt_area(
                &mut buf,
                self.unit_size as usize,
                item.unit_index as u128,
                get_tweak_default,
            );
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_vec(buf),
            });
        }
        Ok(out)
    }
}
