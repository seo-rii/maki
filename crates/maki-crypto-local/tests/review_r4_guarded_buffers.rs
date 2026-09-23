//! R4-002: plaintext and key material must be *born* inside guarded memory.
//!
//! `SecretBuffer` zeroizes on drop and, with `secure-buffers`, pins its pages
//! for its whole lifetime. That guarantee is void for bytes that first existed
//! in an ordinary `Vec` and were wrapped afterwards: the allocating AEAD API
//! decrypts into an unlocked vector, XTS copied through one, and key files
//! were read into one. The fix allocates the guarded buffer first and
//! encrypts, decrypts or reads *in place*. `unguarded_wraps()` counts every
//! `SecretBuffer::from_vec`; it must not move while these paths run.

// The process-global counter is measured under one lock for the whole test
// body; the local providers never yield inside their batch calls.
#![allow(clippy::await_holding_lock)]

use std::sync::{Mutex, MutexGuard, OnceLock};

use maki_crypto::{
    secret::unguarded_wraps, CiphertextUnit, CryptoContext, CryptoError, CryptoProvider,
    PlaintextUnit, SecretBuffer,
};
use maki_crypto_local::keysource::{EnvKeySource, FileKeySource, KeySource, MapKeySource};
use maki_crypto_local::{AesGcmSivProvider, AesXtsProvider};

const UNIT: u32 = 4096;
const UNITS: u64 = 8;

/// The counter is process-global; every test here measures a delta.
fn serial() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
        .lock()
        .unwrap_or_else(|p| p.into_inner())
}

fn ctx(compat: &str) -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0x4242),
        format_version: 1,
        crypto_compatibility_id: compat.to_string(),
    }
}

fn keys() -> MapKeySource {
    let mut keys = MapKeySource::new();
    keys.insert("gcm", (0..32u8).collect());
    keys.insert("xts", (0..64u8).collect());
    keys
}

fn plaintexts() -> Vec<PlaintextUnit> {
    (0..UNITS)
        .map(|unit| {
            let pattern: Vec<u8> = (0..UNIT).map(|i| (i as u8) ^ (unit as u8)).collect();
            PlaintextUnit {
                unit_index: unit,
                data: SecretBuffer::from_slice(&pattern),
            }
        })
        .collect()
}

async fn round_trip_without_unguarded_wraps(
    provider: &dyn CryptoProvider,
    context: &CryptoContext,
) -> Vec<CiphertextUnit> {
    let items = plaintexts();
    let before = unguarded_wraps();
    let cts = provider.encrypt_batch(context, &items).await.unwrap();
    assert_eq!(
        unguarded_wraps(),
        before,
        "encryption must copy plaintext into guarded memory, never through a bare Vec"
    );
    let pts = provider.decrypt_batch(context, &cts).await.unwrap();
    assert_eq!(
        unguarded_wraps(),
        before,
        "decryption must produce plaintext inside a pre-allocated guarded buffer"
    );
    assert_eq!(pts.len(), items.len());
    for (decrypted, original) in pts.iter().zip(items.iter()) {
        assert_eq!(decrypted.unit_index, original.unit_index);
        assert_eq!(decrypted.data, original.data);
        assert_eq!(decrypted.data.len(), UNIT as usize);
    }
    cts
}

#[tokio::test]
async fn gcm_siv_encrypts_and_decrypts_inside_guarded_buffers() {
    let _serial = serial();
    let provider = AesGcmSivProvider::new(&keys(), "gcm", UNIT, "gcm-v1").unwrap();
    let context = ctx("gcm-v1");
    let cts = round_trip_without_unguarded_wraps(&provider, &context).await;

    // Authentication still fails closed on a tampered body, tag and nonce,
    // and the failure path creates no unguarded plaintext either.
    let before = unguarded_wraps();
    for position in [12usize, cts[0].data.len() - 1, 0] {
        let mut tampered = cts[0].data.clone();
        tampered[position] ^= 0x01;
        let result = provider
            .decrypt_batch(
                &context,
                &[CiphertextUnit {
                    unit_index: 0,
                    data: tampered,
                }],
            )
            .await;
        assert!(matches!(result, Err(CryptoError::Integrity(_))), "{result:?}");
    }
    assert_eq!(unguarded_wraps(), before);

    // A ciphertext that is too short to hold a tag is refused before any
    // buffer is allocated.
    let short = CiphertextUnit {
        unit_index: 0,
        data: vec![0; 20],
    };
    assert!(matches!(
        provider.decrypt_batch(&context, &[short]).await,
        Err(CryptoError::Integrity(_))
    ));
}

#[tokio::test]
async fn xts_encrypts_and_decrypts_inside_guarded_buffers() {
    let _serial = serial();
    let provider = AesXtsProvider::new(&keys(), "xts", UNIT, "xts-v1").unwrap();
    let context = ctx("xts-v1");
    let cts = round_trip_without_unguarded_wraps(&provider, &context).await;
    assert_eq!(cts[0].data.len(), UNIT as usize, "XTS is length-preserving");
}

#[test]
fn file_key_source_loads_raw_and_hex_keys_into_guarded_memory() {
    let _serial = serial();
    let dir = tempfile::tempdir().unwrap();
    let raw: Vec<u8> = (100..132u8).collect();
    let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
    for (name, contents) in [("raw", raw.clone()), ("hex", format!("{hex}\n").into_bytes())] {
        let path = dir.path().join(name);
        std::fs::write(&path, contents).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    let source = FileKeySource::new(dir.path());
    let before = unguarded_wraps();
    let loaded_raw = source.load("raw").unwrap();
    let loaded_hex = source.load("hex").unwrap();
    assert_eq!(
        unguarded_wraps(),
        before,
        "key files must be read and hex-decoded into guarded buffers"
    );
    assert_eq!(loaded_raw.expose(), &raw[..]);
    assert_eq!(loaded_hex.expose(), &raw[..]);
}

#[test]
fn env_key_source_copies_the_variable_into_guarded_memory() {
    let _serial = serial();
    let raw: Vec<u8> = (7..39u8).collect();
    let hex: String = raw.iter().map(|b| format!("{b:02X}")).collect();
    std::env::set_var("MAKI_CREDENTIAL_R4_GUARDED", &hex);
    let before = unguarded_wraps();
    let loaded = EnvKeySource.load("r4-guarded").unwrap();
    assert_eq!(unguarded_wraps(), before);
    assert_eq!(loaded.expose(), &raw[..]);
    std::env::remove_var("MAKI_CREDENTIAL_R4_GUARDED");
}
