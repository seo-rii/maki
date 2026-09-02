//! Phase 2 — local crypto providers (SPEC §17, §44).

use maki_crypto::selftest::{cross_endpoint_self_test, provider_conformance, provider_self_test};
use maki_crypto::{
    Capability, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_local::keysource::{KeySource, MapKeySource};
use maki_crypto_local::{AesGcmSivProvider, AesXtsProvider};

const UNIT: usize = 4096;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xFEED_BEEF),
        format_version: 1,
        crypto_compatibility_id: "local-gcm-siv-v1".to_string(),
    }
}

fn xts_ctx() -> CryptoContext {
    CryptoContext {
        crypto_compatibility_id: "local-xts-v1".to_string(),
        ..ctx()
    }
}

fn keys() -> MapKeySource {
    let mut m = MapKeySource::new();
    m.insert("vol-key", vec![0x11; 32]);
    m.insert("vol-key-2", vec![0x22; 32]);
    m.insert("xts-key", vec![0x33; 64]);
    m.insert("short-key", vec![0x44; 16]);
    m
}

fn gcm(key: &str) -> AesGcmSivProvider {
    AesGcmSivProvider::new(&keys(), key, UNIT as u32, "local-gcm-siv-v1").unwrap()
}

fn pt(unit_index: u64, fill: u8) -> PlaintextUnit {
    PlaintextUnit {
        unit_index,
        data: SecretBuffer::from_slice(&vec![fill; UNIT]),
    }
}

// ---------- round trip ----------

#[tokio::test]
async fn gcm_siv_round_trip() {
    let p = gcm("vol-key");
    let cts = p
        .encrypt_batch(
            &ctx(),
            &[pt(0, 0x00), pt(9, 0xAB), pt(u64::MAX / 4096, 0xFF)],
        )
        .await
        .unwrap();
    let caps = p.capabilities().await.unwrap();
    for ct in &cts {
        assert!(ct.data.len() <= caps.max_ciphertext_size as usize);
        assert_ne!(&ct.data[..UNIT.min(ct.data.len())], &vec![0xAB; UNIT][..]);
    }
    let pts = p.decrypt_batch(&ctx(), &cts).await.unwrap();
    assert_eq!(pts[1].data.expose(), &vec![0xAB; UNIT][..]);
    assert_eq!(pts[0].data.expose(), &vec![0x00; UNIT][..]);
}

#[tokio::test]
async fn xts_round_trip() {
    let p = AesXtsProvider::new(&keys(), "xts-key", UNIT as u32, "local-xts-v1").unwrap();
    let cts = p
        .encrypt_batch(&xts_ctx(), &[pt(0, 0x5A), pt(77, 0x5A)])
        .await
        .unwrap();
    // XTS: ciphertext length equals plaintext length.
    assert_eq!(cts[0].data.len(), UNIT);
    // Same plaintext at different units yields different ciphertext (tweak).
    assert_ne!(cts[0].data, cts[1].data);
    let pts = p.decrypt_batch(&xts_ctx(), &cts).await.unwrap();
    assert_eq!(pts[0].data.expose(), &vec![0x5A; UNIT][..]);
    assert_eq!(pts[1].data.expose(), &vec![0x5A; UNIT][..]);
}

// ---------- randomized / corrupted ciphertext ----------

#[tokio::test]
async fn gcm_siv_rejects_corrupt_and_random_ciphertext() {
    let p = gcm("vol-key");
    let mut cts = p.encrypt_batch(&ctx(), &[pt(5, 0x77)]).await.unwrap();

    // Flip one bit anywhere: must fail integrity, never return plaintext.
    let len = cts[0].data.len();
    cts[0].data[len / 2] ^= 0x01;
    let err = p.decrypt_batch(&ctx(), &cts).await.unwrap_err();
    assert!(matches!(err, CryptoError::Integrity(_)), "{err:?}");

    // Pure garbage of plausible size.
    let garbage = maki_crypto::CiphertextUnit {
        unit_index: 5,
        data: vec![0xDD; len],
    };
    assert!(p.decrypt_batch(&ctx(), &[garbage]).await.is_err());
}

#[tokio::test]
async fn xts_declares_no_integrity() {
    // SPEC §17: AES-XTS MUST be documented as not providing authenticated
    // integrity — its capabilities must say so, and the volume layer
    // compensates with slot CRCs.
    let p = AesXtsProvider::new(&keys(), "xts-key", UNIT as u32, "local-xts-v1").unwrap();
    let caps = p.capabilities().await.unwrap();
    assert_eq!(caps.integrity, Capability::Absent);
    assert_eq!(caps.replay_protection, Capability::Absent);
}

// ---------- context binding (SPEC §17 AAD) ----------

#[tokio::test]
async fn gcm_siv_binds_unit_index_volume_and_profile() {
    let p = gcm("vol-key");
    let cts = p.encrypt_batch(&ctx(), &[pt(3, 0x42)]).await.unwrap();
    let caps = p.capabilities().await.unwrap();
    assert_eq!(caps.integrity, Capability::Verified);
    assert_eq!(caps.context_binding, Capability::Verified);

    // Moved to another unit index → reject.
    let moved = maki_crypto::CiphertextUnit {
        unit_index: 4,
        data: cts[0].data.clone(),
    };
    assert!(p.decrypt_batch(&ctx(), &[moved]).await.is_err());

    // Different volume UUID → reject.
    let other_volume = CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xDEAD),
        ..ctx()
    };
    assert!(p.decrypt_batch(&other_volume, &cts).await.is_err());

    // Different compatibility id → reject.
    let other_profile = CryptoContext {
        crypto_compatibility_id: "local-gcm-siv-v2".to_string(),
        ..ctx()
    };
    assert!(p.decrypt_batch(&other_profile, &cts).await.is_err());
}

// ---------- key handling ----------

#[test]
fn wrong_key_length_fails_closed() {
    assert!(AesGcmSivProvider::new(&keys(), "short-key", UNIT as u32, "x").is_err());
    assert!(AesGcmSivProvider::new(&keys(), "xts-key", UNIT as u32, "x").is_err()); // 64B into 32B
    assert!(AesXtsProvider::new(&keys(), "vol-key", UNIT as u32, "x").is_err()); // 32B into 64B
    assert!(AesGcmSivProvider::new(&keys(), "no-such-key", UNIT as u32, "x").is_err());
}

#[test]
fn file_key_source_reads_raw_and_hex() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("raw-key"), vec![0xAA; 32]).unwrap();
    std::fs::write(dir.path().join("hex-key"), format!("{}\n", "ab".repeat(32))).unwrap();
    let src = maki_crypto_local::keysource::FileKeySource::new(dir.path());
    assert_eq!(src.load("raw-key").unwrap().expose(), &vec![0xAA; 32][..]);
    assert_eq!(src.load("hex-key").unwrap().expose(), &vec![0xAB; 32][..]);
    assert!(src.load("missing").is_err());
    // path traversal in credential names is rejected
    assert!(src.load("../etc/passwd").is_err());
}

#[tokio::test]
async fn different_key_cannot_decrypt() {
    let a = gcm("vol-key");
    let b = gcm("vol-key-2");
    let cts = a.encrypt_batch(&ctx(), &[pt(1, 0x10)]).await.unwrap();
    assert!(b.decrypt_batch(&ctx(), &cts).await.is_err());
}

// ---------- self-test & cross-endpoint ----------

#[tokio::test]
async fn local_providers_pass_self_test() {
    provider_self_test(&gcm("vol-key"), &ctx(), UNIT, "local-gcm-siv-v1")
        .await
        .unwrap();
    let xts = AesXtsProvider::new(&keys(), "xts-key", UNIT as u32, "local-xts-v1").unwrap();
    provider_self_test(&xts, &xts_ctx(), UNIT, "local-xts-v1")
        .await
        .unwrap();
}

#[tokio::test]
async fn cross_endpoint_same_key_passes_different_key_fails() {
    let a = gcm("vol-key");
    let b = gcm("vol-key");
    cross_endpoint_self_test(&a, &b, &ctx(), UNIT)
        .await
        .unwrap();
    let c = gcm("vol-key-2");
    assert!(cross_endpoint_self_test(&a, &c, &ctx(), UNIT)
        .await
        .is_err());
}

// ---------- secret leakage ----------

#[test]
fn secrets_never_appear_in_debug_output() {
    let key_material = [0x11u8; 32];
    let provider = gcm("vol-key");
    let rendered = format!("{provider:?}");
    let hexed = key_material
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert!(!rendered.contains(&hexed), "provider Debug leaks key");
    assert!(
        !rendered.contains("17, 17, 17"),
        "provider Debug leaks key bytes"
    );

    let unit = PlaintextUnit {
        unit_index: 1,
        data: SecretBuffer::from_slice(b"top-secret-plaintext"),
    };
    let rendered = format!("{unit:?}");
    assert!(
        !rendered.contains("top-secret"),
        "plaintext leaked: {rendered}"
    );
    assert!(rendered.contains("redacted"));
}

#[tokio::test]
async fn error_messages_never_contain_plaintext_or_key() {
    let p = gcm("vol-key");
    let mut cts = p.encrypt_batch(&ctx(), &[pt(2, 0x99)]).await.unwrap();
    let len = cts[0].data.len();
    cts[0].data[len - 1] ^= 1;
    let err = p.decrypt_batch(&ctx(), &cts).await.unwrap_err();
    let msg = format!("{err}");
    assert!(!msg.contains("99, 99"), "error leaks plaintext: {msg}");
    assert!(!msg.contains("11, 11"), "error leaks key: {msg}");
}

/// Every transport must pass the same provider conformance suite (SPEC §51).
#[tokio::test]
async fn local_providers_pass_conformance() {
    provider_conformance(&gcm("vol-key"), &ctx(), UNIT, "local-gcm-siv-v1")
        .await
        .unwrap();
    let xts = AesXtsProvider::new(&keys(), "xts-key", UNIT as u32, "local-xts-v1").unwrap();
    provider_conformance(&xts, &xts_ctx(), UNIT, "local-xts-v1")
        .await
        .unwrap();
}
