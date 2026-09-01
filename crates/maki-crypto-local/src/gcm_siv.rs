//! AES-256-GCM-SIV provider (SPEC §17).
//!
//! Ciphertext layout: `nonce[12] ‖ aead_ciphertext(pt) ‖ tag[16]` (28 bytes
//! overhead). AAD binds volume UUID, crypto unit index, format version, and
//! crypto compatibility ID, so ciphertext relocated to another unit, volume,
//! or profile fails authentication.

use aes_gcm_siv::aead::{Aead, KeyInit, Payload};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use async_trait::async_trait;
use rand::RngCore;

use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, SecretBuffer,
};

use crate::keysource::KeySource;

const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
pub const GCM_SIV_OVERHEAD: u32 = (NONCE_LEN + TAG_LEN) as u32;

pub struct AesGcmSivProvider {
    cipher: Aes256GcmSiv,
    unit_size: u32,
    compatibility_id: String,
    key_name: String,
}

impl std::fmt::Debug for AesGcmSivProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcmSivProvider")
            .field("unit_size", &self.unit_size)
            .field("compatibility_id", &self.compatibility_id)
            .field("key_name", &self.key_name)
            .field("key", &"<redacted>")
            .finish()
    }
}

impl AesGcmSivProvider {
    pub fn new(
        keys: &dyn KeySource,
        key_name: &str,
        unit_size: u32,
        compatibility_id: &str,
    ) -> Result<Self, CryptoError> {
        let key = keys.load(key_name)?;
        if key.len() != 32 {
            return Err(CryptoError::ProviderFatal(format!(
                "AES-256-GCM-SIV key {key_name:?} has wrong length {} (need 32 bytes)",
                key.len()
            )));
        }
        let cipher = Aes256GcmSiv::new_from_slice(key.expose())
            .map_err(|_| CryptoError::ProviderFatal("cipher init failed".to_string()))?;
        Ok(Self {
            cipher,
            unit_size,
            compatibility_id: compatibility_id.to_string(),
            key_name: key_name.to_string(),
        })
    }

    fn aad(&self, context: &CryptoContext, unit_index: u64) -> Vec<u8> {
        let mut aad = Vec::with_capacity(16 + 8 + 4 + context.crypto_compatibility_id.len());
        aad.extend_from_slice(context.volume_uuid.as_bytes());
        aad.extend_from_slice(&unit_index.to_le_bytes());
        aad.extend_from_slice(&context.format_version.to_le_bytes());
        aad.extend_from_slice(context.crypto_compatibility_id.as_bytes());
        aad
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
impl CryptoProvider for AesGcmSivProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(CryptoCapabilities {
            provider_id: "local-aes-256-gcm-siv".to_string(),
            crypto_compatibility_id: self.compatibility_id.clone(),
            supported_plaintext_sizes: vec![self.unit_size],
            max_ciphertext_size: self.unit_size + GCM_SIV_OVERHEAD,
            stateless: true,
            retry_safe: true,
            batch: BatchCapability {
                supported: true,
                max_items: 4096,
                max_bytes: 64 << 20,
            },
            integrity: Capability::Verified,
            context_binding: Capability::Verified,
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
        let mut rng = rand::rng();
        for item in items {
            let pt = item.data.expose();
            if pt.len() != self.unit_size as usize {
                return Err(CryptoError::NonRetryableRequest(format!(
                    "unsupported plaintext size {}",
                    pt.len()
                )));
            }
            let mut nonce = [0u8; NONCE_LEN];
            rng.fill_bytes(&mut nonce);
            let aad = self.aad(context, item.unit_index);
            let ct = self
                .cipher
                .encrypt(
                    Nonce::from_slice(&nonce),
                    Payload { msg: pt, aad: &aad },
                )
                .map_err(|_| CryptoError::ProviderFatal("AEAD encryption failed".to_string()))?;
            let mut data = Vec::with_capacity(NONCE_LEN + ct.len());
            data.extend_from_slice(&nonce);
            data.extend_from_slice(&ct);
            out.push(CiphertextUnit {
                unit_index: item.unit_index,
                data,
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
            if item.data.len() < NONCE_LEN + TAG_LEN {
                return Err(CryptoError::Integrity(
                    "ciphertext too short".to_string(),
                ));
            }
            let (nonce, body) = item.data.split_at(NONCE_LEN);
            let aad = self.aad(context, item.unit_index);
            let pt = self
                .cipher
                .decrypt(
                    Nonce::from_slice(nonce),
                    Payload {
                        msg: body,
                        aad: &aad,
                    },
                )
                // Never include any data in the message: authentication
                // failure yields no information.
                .map_err(|_| {
                    CryptoError::Integrity("AEAD authentication failed".to_string())
                })?;
            if pt.len() != self.unit_size as usize {
                return Err(CryptoError::Integrity(
                    "decrypted length mismatch".to_string(),
                ));
            }
            out.push(PlaintextUnit {
                unit_index: item.unit_index,
                data: SecretBuffer::from_vec(pt),
            });
        }
        Ok(out)
    }
}
