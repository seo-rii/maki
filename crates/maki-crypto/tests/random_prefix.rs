use std::{
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use maki_crypto::{
    BatchCapability, Capability, CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError,
    CryptoProvider, PlaintextUnit, RandomPrefixProvider, SecretBuffer,
};
use uuid::Uuid;

const LOGICAL: u32 = 32;
const PREFIX: u32 = 16;
const WIRE: u32 = LOGICAL + PREFIX;

#[derive(Debug, Clone)]
struct Call {
    context: CryptoContext,
    indices: Vec<u64>,
    plaintexts: Vec<Vec<u8>>,
}

struct RecordingProvider {
    caps: CryptoCapabilities,
    calls: Mutex<Vec<Call>>,
    deadline: Option<Duration>,
    encrypt_error: bool,
    encrypt_shape: Mutex<Option<&'static str>>,
    decrypt_shape: Mutex<Option<&'static str>>,
}

impl RecordingProvider {
    fn new() -> Self {
        Self {
            caps: CryptoCapabilities {
                provider_id: "fake".into(),
                crypto_compatibility_id: "base-v1".into(),
                supported_plaintext_sizes: vec![WIRE],
                max_ciphertext_size: WIRE + 12,
                stateless: true,
                retry_safe: true,
                batch: BatchCapability {
                    supported: true,
                    max_items: 4,
                    max_bytes: (WIRE * 3) as u64,
                },
                integrity: Capability::Verified,
                context_binding: Capability::Contractual,
                replay_protection: Capability::Absent,
            },
            calls: Mutex::new(Vec::new()),
            deadline: Some(Duration::from_secs(7)),
            encrypt_error: false,
            encrypt_shape: Mutex::new(None),
            decrypt_shape: Mutex::new(None),
        }
    }
}

#[async_trait]
impl CryptoProvider for RecordingProvider {
    fn max_operation_time(&self) -> Option<Duration> {
        self.deadline
    }
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        Ok(self.caps.clone())
    }
    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.calls.lock().unwrap().push(Call {
            context: context.clone(),
            indices: items.iter().map(|x| x.unit_index).collect(),
            plaintexts: items.iter().map(|x| x.data.expose().to_vec()).collect(),
        });
        if self.encrypt_error {
            return Err(CryptoError::Retryable("again".into()));
        }
        let mut out: Vec<_> = items
            .iter()
            .map(|x| CiphertextUnit {
                unit_index: x.unit_index,
                data: x.data.expose().to_vec(),
            })
            .collect();
        match self.encrypt_shape.lock().unwrap().take() {
            Some("missing") => {
                out.pop();
            }
            Some("reordered") => out.reverse(),
            _ => {}
        }
        Ok(out)
    }
    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        let mut out: Vec<_> = items
            .iter()
            .map(|x| PlaintextUnit {
                unit_index: x.unit_index,
                data: SecretBuffer::from_slice(&x.data),
            })
            .collect();
        match self.decrypt_shape.lock().unwrap().take() {
            Some("missing") => {
                out.pop();
            }
            Some("reordered") => out.reverse(),
            Some("short") => out[0].data = SecretBuffer::zeroed((WIRE - 1) as usize),
            _ => {}
        }
        self.calls.lock().unwrap().push(Call {
            context: context.clone(),
            indices: items.iter().map(|x| x.unit_index).collect(),
            plaintexts: vec![],
        });
        Ok(out)
    }
}

fn context(id: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: Uuid::from_u128(42),
        format_version: 9,
        crypto_compatibility_id: id.into(),
    }
}
fn units() -> Vec<PlaintextUnit> {
    vec![
        PlaintextUnit {
            unit_index: 8,
            data: SecretBuffer::from_slice(&[0x31; LOGICAL as usize]),
        },
        PlaintextUnit {
            unit_index: 2,
            data: SecretBuffer::from_slice(&[0x72; LOGICAL as usize]),
        },
    ]
}

#[tokio::test]
async fn prefixes_each_item_fresh_and_translates_only_compatibility_id() {
    let inner = Arc::new(RecordingProvider::new());
    let wrapper = RandomPrefixProvider::new(inner.clone(), LOGICAL, PREFIX, "outer-v1".into())
        .await
        .unwrap();
    let first = wrapper
        .encrypt_batch(&context("outer-v1"), &units())
        .await
        .unwrap();
    let second = wrapper
        .encrypt_batch(&context("outer-v1"), &units())
        .await
        .unwrap();
    assert_ne!(
        &first[0].data[..PREFIX as usize],
        &first[1].data[..PREFIX as usize]
    );
    assert_ne!(
        &first[0].data[..PREFIX as usize],
        &second[0].data[..PREFIX as usize]
    );
    assert_eq!(&first[0].data[PREFIX as usize..], &[0x31; LOGICAL as usize]);
    let calls = inner.calls.lock().unwrap();
    assert_eq!(calls[0].context, context("base-v1"));
    assert_eq!(calls[0].indices, vec![8, 2]);
    assert_eq!(calls[0].plaintexts[1].len(), WIRE as usize);
}

#[tokio::test]
async fn roundtrip_strips_prefix_and_preserves_order() {
    let wrapper = RandomPrefixProvider::new(
        Arc::new(RecordingProvider::new()),
        LOGICAL,
        PREFIX,
        "outer-v1".into(),
    )
    .await
    .unwrap();
    let ciphertext = wrapper
        .encrypt_batch(&context("outer-v1"), &units())
        .await
        .unwrap();
    let plaintext = wrapper
        .decrypt_batch(&context("outer-v1"), &ciphertext)
        .await
        .unwrap();
    assert_eq!(
        plaintext.iter().map(|x| x.unit_index).collect::<Vec<_>>(),
        vec![8, 2]
    );
    assert_eq!(plaintext[0].data.expose(), &[0x31; LOGICAL as usize]);
    assert_eq!(plaintext[1].data.expose(), &[0x72; LOGICAL as usize]);
}

#[tokio::test]
async fn advertises_logical_capabilities_and_forwards_deadline() {
    let wrapper = RandomPrefixProvider::new(
        Arc::new(RecordingProvider::new()),
        LOGICAL,
        PREFIX,
        "outer-v1".into(),
    )
    .await
    .unwrap();
    let caps = wrapper.capabilities().await.unwrap();
    assert_eq!(caps.crypto_compatibility_id, "outer-v1");
    assert_eq!(caps.supported_plaintext_sizes, vec![LOGICAL]);
    assert_eq!(caps.max_ciphertext_size, WIRE + 12);
    assert_eq!(
        caps.batch,
        BatchCapability {
            supported: true,
            max_items: 3,
            max_bytes: 3 * LOGICAL as u64
        }
    );
    assert_eq!(caps.integrity, Capability::Verified);
    assert_eq!(wrapper.max_operation_time(), Some(Duration::from_secs(7)));
}

#[tokio::test]
async fn rejects_invalid_configuration() {
    for prefix in [0, 15, 17, 272] {
        assert!(RandomPrefixProvider::new(
            Arc::new(RecordingProvider::new()),
            LOGICAL,
            prefix,
            "outer-v1".into()
        )
        .await
        .is_err());
    }
    assert!(RandomPrefixProvider::new(
        Arc::new(RecordingProvider::new()),
        0,
        PREFIX,
        "outer-v1".into()
    )
    .await
    .is_err());
    assert!(RandomPrefixProvider::new(
        Arc::new(RecordingProvider::new()),
        LOGICAL,
        PREFIX,
        String::new()
    )
    .await
    .is_err());
    assert!(RandomPrefixProvider::new(
        Arc::new(RecordingProvider::new()),
        LOGICAL,
        PREFIX,
        "base-v1".into()
    )
    .await
    .is_err());
    let mut bad = RecordingProvider::new();
    bad.caps.supported_plaintext_sizes.clear();
    assert!(
        RandomPrefixProvider::new(Arc::new(bad), LOGICAL, PREFIX, "outer-v1".into())
            .await
            .is_err()
    );
    let mut no_items = RecordingProvider::new();
    no_items.caps.batch = BatchCapability {
        supported: false,
        max_items: 0,
        max_bytes: u64::MAX,
    };
    assert!(
        RandomPrefixProvider::new(Arc::new(no_items), LOGICAL, PREFIX, "outer-v1".into())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn rejects_bad_inputs_before_invoking_inner() {
    let inner = Arc::new(RecordingProvider::new());
    let wrapper = RandomPrefixProvider::new(inner.clone(), LOGICAL, PREFIX, "outer-v1".into())
        .await
        .unwrap();
    let bad = [PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::zeroed(LOGICAL as usize - 1),
    }];
    assert!(matches!(
        wrapper.encrypt_batch(&context("outer-v1"), &bad).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
    assert!(matches!(
        wrapper.encrypt_batch(&context("wrong"), &units()).await,
        Err(CryptoError::UnsupportedContext(_))
    ));
    assert!(inner.calls.lock().unwrap().is_empty());
    let four: Vec<_> = (0..4)
        .map(|i| PlaintextUnit {
            unit_index: i,
            data: SecretBuffer::zeroed(LOGICAL as usize),
        })
        .collect();
    assert!(matches!(
        wrapper.encrypt_batch(&context("outer-v1"), &four).await,
        Err(CryptoError::NonRetryableRequest(_))
    ));
}

#[tokio::test]
async fn rejects_empty_and_oversize_ciphertext_before_invoking_inner() {
    let inner = Arc::new(RecordingProvider::new());
    let wrapper = RandomPrefixProvider::new(inner.clone(), LOGICAL, PREFIX, "outer-v1".into())
        .await
        .unwrap();
    for data in [vec![], vec![0; (WIRE + 13) as usize]] {
        let ciphertext = [CiphertextUnit {
            unit_index: 4,
            data,
        }];
        assert!(matches!(
            wrapper
                .decrypt_batch(&context("outer-v1"), &ciphertext)
                .await,
            Err(CryptoError::NonRetryableRequest(_))
        ));
    }
    assert!(inner.calls.lock().unwrap().is_empty());
}

#[tokio::test]
async fn rejects_malformed_inner_decrypt_results_without_plaintext() {
    for shape in ["missing", "reordered", "short"] {
        let inner = Arc::new(RecordingProvider::new());
        *inner.decrypt_shape.lock().unwrap() = Some(shape);
        let wrapper = RandomPrefixProvider::new(inner, LOGICAL, PREFIX, "outer-v1".into())
            .await
            .unwrap();
        let ciphertext = vec![
            CiphertextUnit {
                unit_index: 1,
                data: vec![4; WIRE as usize],
            },
            CiphertextUnit {
                unit_index: 2,
                data: vec![5; WIRE as usize],
            },
        ];
        assert!(matches!(
            wrapper
                .decrypt_batch(&context("outer-v1"), &ciphertext)
                .await,
            Err(CryptoError::Contract(_))
        ));
    }
}

#[tokio::test]
async fn rejects_malformed_inner_encrypt_results() {
    for shape in ["missing", "reordered"] {
        let inner = Arc::new(RecordingProvider::new());
        *inner.encrypt_shape.lock().unwrap() = Some(shape);
        let wrapper = RandomPrefixProvider::new(inner, LOGICAL, PREFIX, "outer-v1".into())
            .await
            .unwrap();
        assert!(matches!(
            wrapper.encrypt_batch(&context("outer-v1"), &units()).await,
            Err(CryptoError::Contract(_))
        ));
    }
}

#[tokio::test]
async fn unsupported_inner_batch_has_one_item_outer_semantics() {
    let mut fake = RecordingProvider::new();
    fake.caps.batch = BatchCapability {
        supported: false,
        max_items: 99,
        max_bytes: u64::MAX,
    };
    let wrapper = RandomPrefixProvider::new(Arc::new(fake), LOGICAL, PREFIX, "outer-v1".into())
        .await
        .unwrap();
    let caps = wrapper.capabilities().await.unwrap();
    assert_eq!(
        caps.batch,
        BatchCapability {
            supported: false,
            max_items: 1,
            max_bytes: LOGICAL as u64
        }
    );
    assert!(wrapper
        .encrypt_batch(&context("outer-v1"), &units())
        .await
        .is_err());
}

#[tokio::test]
async fn forwards_inner_errors_unchanged() {
    let mut fake = RecordingProvider::new();
    fake.encrypt_error = true;
    let wrapper = RandomPrefixProvider::new(Arc::new(fake), LOGICAL, PREFIX, "outer-v1".into())
        .await
        .unwrap();
    assert!(
        matches!(wrapper.encrypt_batch(&context("outer-v1"), &units()).await, Err(CryptoError::Retryable(message)) if message == "again")
    );
}
