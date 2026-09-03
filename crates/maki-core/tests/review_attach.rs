//! Regression tests for review M-001: a wrong key or provider must be
//! rejected at attach, before any data is served (SPEC §12 "crypto profile
//! mismatch prevents attach").
//!
//! The volume's key canary is established at first attach and verified on
//! every later one; the configured identity strings are compared with the
//! superblock. The fake provider stands in for both an authenticated cipher
//! (default) and an unauthenticated one (`with_integrity_check(false)`,
//! which decrypts under a wrong key to garbage without an error, like XTS).

use std::sync::Arc;

use async_trait::async_trait;
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{AttachError, AttachIdentity, Engine, EngineOptions};
use maki_core::volume::{Volume, VolumeOptions};
use maki_crypto::{
    CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit,
    SecretBuffer,
};
use maki_format::ab::AbStore;
use maki_format::canary::{KeyCanary, CANARY_UNIT_INDEX};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const BLOCK: u32 = 512;
const UNIT: u32 = 2048;
const DEVICE_SIZE: u64 = 256 * UNIT as u64;
const KEY_A: u64 = 0xA11CE;
const KEY_B: u64 = 0xB0B;

fn geometry() -> Geometry {
    Geometry::compute(BLOCK, UNIT, 512, UNIT + 8, DEVICE_SIZE, 64 * UNIT as u64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xCA11),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn context() -> CryptoContext {
    CryptoContext {
        volume_uuid: superblock().volume_uuid,
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".into(),
    }
}

fn key(seed: u64) -> Arc<FakeCryptoProvider> {
    Arc::new(FakeCryptoProvider::new(UNIT).with_key(seed))
}

fn unauthenticated_key(seed: u64) -> Arc<FakeCryptoProvider> {
    Arc::new(
        FakeCryptoProvider::new(UNIT)
            .with_key(seed)
            .with_integrity_check(false),
    )
}

fn options(identity: Option<AttachIdentity>) -> EngineOptions {
    EngineOptions {
        volume: VolumeOptions {
            journal_segment_size: 1 << 20,
        },
        identity,
        ..Default::default()
    }
}

async fn attach(
    backing: &Arc<CrashableBacking>,
    provider: Arc<dyn CryptoProvider>,
) -> Result<Engine, AttachError> {
    Engine::attach(backing.clone() as Arc<dyn Backing>, provider, options(None)).await
}

async fn attach_as(
    backing: &Arc<CrashableBacking>,
    provider: Arc<dyn CryptoProvider>,
    provider_type: &str,
    key_identity: &str,
) -> Result<Engine, AttachError> {
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider,
        options(Some(AttachIdentity {
            provider_type: provider_type.into(),
            key_identity: key_identity.into(),
        })),
    )
    .await
}

fn fresh() -> Arc<CrashableBacking> {
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    backing
}

fn canary_present(backing: &CrashableBacking) -> bool {
    AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B)
        .load::<KeyCanary>(backing)
        .unwrap()
        .is_some()
}

fn data(stamp: u8) -> Vec<u8> {
    vec![stamp; UNIT as usize]
}

async fn write_and_checkpoint(engine: &Engine, stamp: u8) {
    engine.write(0, &data(stamp), true).await.unwrap();
    engine.checkpoint().await.unwrap();
}

// ---------- wrong key ----------

#[tokio::test]
async fn attach_rejects_wrong_key_same_compatibility_id() {
    let backing = fresh();
    let engine = attach(&backing, key(KEY_A)).await.unwrap();
    write_and_checkpoint(&engine, 0x11).await;
    drop(engine);

    match attach(&backing, key(KEY_B)).await {
        Err(AttachError::KeyMismatch(_)) => {}
        Ok(_) => panic!("attach with the wrong key must be refused"),
        Err(e) => panic!("unexpected error: {e}"),
    }
    let engine = attach(&backing, key(KEY_A)).await.unwrap();
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), data(0x11));
}

/// With an unauthenticated cipher the wrong key produces plausible-looking
/// garbage; only the canary comparison can catch it.
#[tokio::test]
async fn attach_rejects_wrong_key_without_provider_integrity() {
    let backing = fresh();
    let engine = attach(&backing, unauthenticated_key(KEY_A)).await.unwrap();
    write_and_checkpoint(&engine, 0x22).await;
    drop(engine);

    match attach(&backing, unauthenticated_key(KEY_B)).await {
        Err(AttachError::KeyMismatch(msg)) => assert!(msg.contains("plaintext"), "{msg}"),
        Ok(_) => panic!("garbage plaintext must not attach"),
        Err(e) => panic!("unexpected error: {e}"),
    }
    let engine = attach(&backing, unauthenticated_key(KEY_A)).await.unwrap();
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), data(0x22));
}

/// The first attach binds the key even when nothing is written, and the
/// binding is durable across a crash.
#[tokio::test]
async fn first_attach_binds_key_durably() {
    let backing = fresh();
    assert!(!canary_present(&backing));
    drop(attach(&backing, key(KEY_A)).await.unwrap());
    assert!(canary_present(&backing));

    backing.crash_all_lost();
    assert!(canary_present(&backing), "canary must be durable");
    assert!(matches!(
        attach(&backing, key(KEY_B)).await,
        Err(AttachError::KeyMismatch(_))
    ));
    attach(&backing, key(KEY_A)).await.unwrap();
}

// ---------- identity strings ----------

#[tokio::test]
async fn attach_rejects_provider_type_change_with_same_compatibility_id() {
    let backing = fresh();
    drop(attach_as(&backing, key(KEY_A), "fake", "k").await.unwrap());
    match attach_as(&backing, key(KEY_A), "local-aes-xts", "k").await {
        Err(AttachError::IdentityMismatch(msg)) => assert!(msg.contains("provider"), "{msg}"),
        other => panic!("expected IdentityMismatch, got {:?}", other.map(|_| ())),
    }
}

#[tokio::test]
async fn attach_rejects_key_identity_change() {
    let backing = fresh();
    drop(attach_as(&backing, key(KEY_A), "fake", "k").await.unwrap());
    match attach_as(&backing, key(KEY_A), "fake", "k-rotated").await {
        Err(AttachError::IdentityMismatch(msg)) => assert!(msg.contains("key identity"), "{msg}"),
        other => panic!("expected IdentityMismatch, got {:?}", other.map(|_| ())),
    }
    attach_as(&backing, key(KEY_A), "fake", "k").await.unwrap();
}

// ---------- volumes written before canaries existed ----------

/// Encrypt one unit with `provider` and journal it directly, bypassing the
/// engine: the state of a volume written before canaries existed.
async fn write_legacy_unit(backing: &Arc<CrashableBacking>, provider: &dyn CryptoProvider) {
    let ct = provider
        .encrypt_batch(
            &context(),
            &[PlaintextUnit {
                unit_index: 0,
                data: SecretBuffer::from_vec(data(0x33)),
            }],
        )
        .await
        .unwrap();
    let mut vol = Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: 1 << 20,
        },
    )
    .unwrap();
    vol.write_ct(0, &ct[0].data, true).unwrap();
    vol.checkpoint().unwrap();
}

#[tokio::test]
async fn legacy_volume_is_probed_with_integrity_provider_then_canaried() {
    let backing = fresh();
    write_legacy_unit(&backing, key(KEY_A).as_ref()).await;
    assert!(!canary_present(&backing));

    match attach(&backing, key(KEY_B)).await {
        Err(AttachError::KeyMismatch(_)) => {}
        other => panic!("wrong key must fail the probe, got {:?}", other.map(|_| ())),
    }
    assert!(!canary_present(&backing), "a failed probe must not bind");

    let engine = attach(&backing, key(KEY_A)).await.unwrap();
    assert_eq!(engine.read(0, UNIT as usize).await.unwrap(), data(0x33));
    drop(engine);
    assert!(
        canary_present(&backing),
        "successful probe establishes the canary"
    );
    assert!(matches!(
        attach(&backing, key(KEY_B)).await,
        Err(AttachError::KeyMismatch(_))
    ));
}

#[tokio::test]
async fn legacy_volume_without_integrity_is_refused() {
    let backing = fresh();
    write_legacy_unit(&backing, unauthenticated_key(KEY_A).as_ref()).await;
    match attach(&backing, unauthenticated_key(KEY_A)).await {
        Err(AttachError::MissingCanary(_)) => {}
        other => panic!("expected MissingCanary, got {:?}", other.map(|_| ())),
    }
    assert!(!canary_present(&backing));
}

// ---------- error classification ----------

/// Fails decrypts of the canary unit with a transport-class error.
struct CanaryUnreachable(Arc<FakeCryptoProvider>);

#[async_trait]
impl CryptoProvider for CanaryUnreachable {
    async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
        self.0.capabilities().await
    }

    async fn encrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[PlaintextUnit],
    ) -> Result<Vec<CiphertextUnit>, CryptoError> {
        self.0.encrypt_batch(context, items).await
    }

    async fn decrypt_batch(
        &self,
        context: &CryptoContext,
        items: &[CiphertextUnit],
    ) -> Result<Vec<PlaintextUnit>, CryptoError> {
        if items.iter().any(|i| i.unit_index == CANARY_UNIT_INDEX) {
            return Err(CryptoError::Retryable("endpoint timed out".to_string()));
        }
        self.0.decrypt_batch(context, items).await
    }
}

#[tokio::test]
async fn canary_transport_failure_is_not_reported_as_key_mismatch() {
    let backing = fresh();
    drop(attach(&backing, key(KEY_A)).await.unwrap());
    match attach(&backing, Arc::new(CanaryUnreachable(key(KEY_A)))).await {
        Err(AttachError::Crypto(e)) => assert!(e.is_retryable(), "{e}"),
        other => panic!("expected a transport error, got {:?}", other.map(|_| ())),
    }
}

/// A canary copied from another volume must not verify.
#[tokio::test]
async fn canary_from_another_volume_is_rejected() {
    let backing = fresh();
    drop(attach(&backing, key(KEY_A)).await.unwrap());
    let ab = AbStore::new(layout::KEY_CANARY_A, layout::KEY_CANARY_B);
    let mut foreign = ab.load::<KeyCanary>(backing.as_ref()).unwrap().unwrap();
    foreign.volume_uuid = Uuid::from_u128(0xDEAD);
    ab.store(backing.as_ref(), &mut foreign).unwrap();
    ab.store(backing.as_ref(), &mut foreign).unwrap();
    assert!(matches!(
        attach(&backing, key(KEY_A)).await,
        Err(AttachError::KeyMismatch(_))
    ));
}
