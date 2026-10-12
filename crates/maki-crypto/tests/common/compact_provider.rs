//! Stateless reversible fixture: uniform units use a compact representation
//! with the fake's integrity/context checks; other units keep full ciphertext.
use async_trait::async_trait;
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_test_support::fake_provider::FakeCryptoProvider;
use std::sync::Mutex;

pub const UNIT: u32 = 4096;
const PACKED: usize = 512;

pub struct CompactProvider {
    full: FakeCryptoProvider,
    packed: FakeCryptoProvider,
    compact: bool,
    max_items: usize,
    max_bytes: u64,
    encrypt_groups: Mutex<Vec<usize>>,
    decrypt_groups: Mutex<Vec<usize>>,
}

impl CompactProvider {
    pub fn new(max_items: u32, max_bytes: u64, compact: bool) -> Self {
        Self {
            full: FakeCryptoProvider::new(UNIT).with_max_batch(max_items, max_bytes),
            packed: FakeCryptoProvider::new(PACKED as u32),
            compact,
            max_items: max_items as usize,
            max_bytes,
            encrypt_groups: Mutex::default(),
            decrypt_groups: Mutex::default(),
        }
    }

    fn admit(&self, count: usize) -> Result<(), CryptoError> {
        let logical = count as u64 * UNIT as u64;
        if count > self.max_items || logical > self.max_bytes {
            return Err(CryptoError::NonRetryableRequest(format!(
                "{count} units / {logical} plaintext bytes exceed fixture limit {} / {}",
                self.max_items, self.max_bytes,
            )));
        }
        Ok(())
    }

    pub fn encrypt_groups(&self) -> Vec<usize> {
        self.encrypt_groups.lock().unwrap().clone()
    }

    pub fn decrypt_groups(&self) -> Vec<usize> {
        self.decrypt_groups.lock().unwrap().clone()
    }
}

#[async_trait]
impl CryptoProvider for CompactProvider {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.full.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.admit(items.len())?;
        self.encrypt_groups.lock().unwrap().push(items.len());
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            let bytes = item.data.expose();
            if self.compact && bytes.len() == UNIT as usize && bytes.iter().all(|b| *b == bytes[0])
            {
                let mut packet = [0; PACKED];
                packet[..4].copy_from_slice(b"RLE1");
                packet[4] = bytes[0];
                let input = PlaintextUnit {
                    unit_index: item.unit_index,
                    data: SecretBuffer::from_slice(&packet),
                };
                out.extend(self.packed.encrypt_batch(context, &[input]).await?);
            } else {
                out.extend(
                    self.full
                        .encrypt_batch(context, std::slice::from_ref(item))
                        .await?,
                );
            }
        }
        Ok(out)
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        self.admit(items.len())?;
        self.decrypt_groups.lock().unwrap().push(items.len());
        let mut out = Vec::with_capacity(items.len());
        for item in items {
            if item.data.len() == PACKED + 8 {
                let decoded = self
                    .packed
                    .decrypt_batch(context, std::slice::from_ref(item))
                    .await?;
                let bytes = decoded[0].data.expose();
                if &bytes[..4] != b"RLE1" || bytes[5..].iter().any(|b| *b != 0) {
                    return Err(CryptoError::Integrity("invalid compact packet".into()));
                }
                out.push(PlaintextUnit {
                    unit_index: item.unit_index,
                    data: SecretBuffer::from_vec(vec![bytes[4]; UNIT as usize]),
                });
            } else {
                out.extend(
                    self.full
                        .decrypt_batch(context, std::slice::from_ref(item))
                        .await?,
                );
            }
        }
        Ok(out)
    }
}
