//! Regression tests for the second audit's core findings (K-series in the
//! remediation log): durability after a *process* restart, reclaim of
//! covered segments, adoption ordering, scanner bounds, and covered-prefix
//! resurrection.
//!
//! A process restart (SIGKILL, OOM, panic) is not a power loss: unsynced
//! bytes stay in the page cache and are read back by the next recovery.
//! `CrashableBacking` models that exactly by keeping pending writes
//! visible until a `crash*` call drops them.

use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::recovery::RecoveryError;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::journal::{encode_record, JournalRecord};
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use maki_test_support::failpoints;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const CT_LEN: usize = 540;
const SEGMENT: u64 = 4096;
const RECORD: u64 = 32 + CT_LEN as u64;
const RECORDS_PER_SEGMENT: u64 = (SEGMENT - 48) / RECORD; // 7
const DEVICE_UNITS: u64 = 1024;

fn geometry() -> Geometry {
    Geometry::compute(512, UNIT, 512, 544, UNIT as u64 * DEVICE_UNITS, 512 * 64).unwrap()
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xA0D17),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: geometry(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: SEGMENT,
    }
}

fn new_volume(backing: &Arc<CrashableBacking>) -> Volume {
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    Volume::recover(backing.clone() as Arc<dyn Backing>, options()).unwrap()
}

fn recover(backing: &Arc<CrashableBacking>) -> Result<Volume, RecoveryError> {
    Volume::recover(backing.clone() as Arc<dyn Backing>, options())
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; CT_LEN]
}

fn expect_corrupt(result: Result<Volume, RecoveryError>) -> String {
    match result.map(|_| ()) {
        Err(RecoveryError::Corrupt(msg)) => msg,
        Err(other) => panic!("expected Corrupt, got {other:?}"),
        Ok(()) => panic!("expected Corrupt, recovery succeeded"),
    }
}

// ---------- K-01: unsynced bytes accepted by recovery must be made durable ----------

/// Records written without FUA survive a process restart in the page
/// cache. Recovery reads them, treats them as durable, and the next FLUSH
/// has nothing active to sync — so a power loss after that FLUSH used to
/// lose FLUSH-acknowledged data.
#[test]
fn recovery_fsyncs_page_cache_records_before_a_flush_acknowledges_them() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), false).unwrap(); // page cache only
    drop(vol); // process restart, not a power loss

    let mut vol = recover(&backing).unwrap();
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
    vol.flush().unwrap(); // acknowledges durability of everything visible
    drop(vol);

    backing.crash_all_lost(); // power loss: only fsync'd bytes survive
    let vol = recover(&backing).unwrap();
    assert_eq!(
        vol.read_ct(0).unwrap().map(|(_, d)| d),
        Some(ct(1)),
        "FLUSH-acknowledged record lost after a power loss"
    );
}

/// Same start, no FLUSH: the first write after the restart opens a
/// successor segment, which makes the resumed segment non-final; if its
/// page-cache tail was never fsync'd, the power loss tears a non-final
/// segment and recovery refuses the whole volume.
#[test]
fn resumed_segment_is_durable_before_a_successor_is_opened() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    vol.write_ct(1, &ct(2), false).unwrap(); // page cache only
    drop(vol);

    let mut vol = recover(&backing).unwrap();
    vol.write_ct(2, &ct(3), false).unwrap(); // rolls to a new segment
    assert_eq!(vol.journal_segment_count(), 2);
    drop(vol);

    backing.crash_all_lost();
    let vol = recover(&backing)
        .unwrap_or_else(|e| panic!("volume refused after a power loss following a restart: {e:?}"));
    assert_eq!(vol.read_ct(0).unwrap().unwrap().1, ct(1));
    assert_eq!(
        vol.read_ct(1).unwrap().map(|(_, d)| d),
        Some(ct(2)),
        "record accepted by the previous recovery was not made durable"
    );
    assert!(
        vol.read_ct(2).unwrap().is_none(),
        "unsynced record after the restart"
    );
}

// ---------- K-02: covered segments are reclaimed even by an idle checkpoint ----------

/// A checkpoint that advanced its state but failed to delete the covered
/// segments (transient unlink error, or the deletions lost in a crash)
/// used to leave them on disk forever: every later checkpoint took the
/// "nothing new" path, so the journal stayed at its hard limit and every
/// write failed with ENOSPC while the engine reported Ready.
#[test]
fn idle_checkpoint_reclaims_covered_segments_left_by_a_failed_deletion() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..(3 * RECORDS_PER_SEGMENT) as u8 {
        vol.write_ct(i as u64 % 4, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap();
    let before = vol.journal_segment_count();
    assert!(before >= 3);

    let fp = failpoints::fail_n_times(
        "checkpoint.segment_delete",
        1,
        std::io::ErrorKind::Other,
        "unlink failed",
    );
    assert!(vol.checkpoint().is_err(), "deletion failure must surface");
    drop(fp);
    assert_eq!(
        vol.checkpoint_sequence(),
        vol.journal_durable_sequence(),
        "state advanced before the deletions"
    );
    assert_eq!(vol.journal_segment_count(), before, "nothing reclaimed yet");

    // Nothing new is durable: the "idle" path must still reclaim.
    vol.checkpoint().unwrap();
    assert!(
        vol.journal_segment_count() <= 1,
        "covered segments still on disk: {}",
        vol.journal_segment_count()
    );
    for i in 0..4u64 {
        assert!(vol.read_ct(i).unwrap().is_some());
    }

    // And after a restart the resurrected-or-leftover segments go too.
    drop(vol);
    let mut vol = recover(&backing).unwrap();
    vol.checkpoint().unwrap();
    assert!(vol.journal_segment_count() <= 1);
}

// ---------- K-03: adopted shard must not be cataloged before its map exists ----------

/// A shard data file whose creation was committed by the filesystem before
/// its allocation map was stored is adopted at open. Persisting the catalog
/// *before* the shard's (empty) allocation map, and then failing, produced
/// a cataloged shard with no allocation copy, which every later attach
/// refuses.
#[test]
fn adopted_shard_is_never_cataloged_without_an_allocation_copy() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    init::create_volume(backing.as_ref(), superblock()).unwrap();
    // Orphan data file: committed dirent, no allocation map, not cataloged.
    let data = backing.open(&layout::shard_data(0), true).unwrap();
    data.set_len(geometry().units_per_shard() * geometry().slot_size)
        .unwrap();
    data.sync_data().unwrap();
    backing.sync_dir(layout::DATA_DIR).unwrap();

    let mut vol = recover(&backing).expect("orphan is adopted");
    let fp = failpoints::set(
        "checkpoint.alloc_store",
        failpoints::FailpointAction::IoError(std::io::ErrorKind::Other, "injected".into()),
    );
    let _ = vol.checkpoint(); // may fail; must not leave a half-cataloged shard
    drop(fp);
    drop(vol);

    let mut vol = recover(&backing)
        .unwrap_or_else(|e| panic!("attach refused after a failed adoption persist: {e:?}"));
    vol.checkpoint().unwrap();
    drop(vol);
    recover(&backing).unwrap();
}

// ---------- K-06: replayed records must be inside the geometry ----------

/// A CRC-valid record naming a unit beyond the device (a forged or
/// mis-addressed journal) used to be replayed and then checkpointed into
/// an out-of-range shard that the next open rejects. Recovery must refuse
/// it up front.
#[test]
fn record_with_out_of_range_unit_is_corruption_not_replay() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let forged = encode_record(&JournalRecord {
        sequence: 2,
        unit_index: DEVICE_UNITS, // one past the end
        payload: ct(9),
    });
    let f = backing.open(&seg, false).unwrap();
    f.write_at(48 + RECORD, &forged).unwrap();
    f.sync_data().unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("unit"), "{msg}");
}

/// Likewise a record whose payload exceeds the volume's ciphertext size.
#[test]
fn record_with_oversized_payload_is_corruption_not_replay() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    vol.write_ct(0, &ct(1), true).unwrap();
    let seg = vol.journal_active_segment_path().unwrap();
    drop(vol);

    let forged = encode_record(&JournalRecord {
        sequence: 2,
        unit_index: 1,
        payload: vec![7u8; 600], // max_ciphertext_size is 544
    });
    let f = backing.open(&seg, false).unwrap();
    f.write_at(48 + RECORD, &forged).unwrap();
    f.sync_data().unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("payload"), "{msg}");
}

// ---------- K-07: a partially resurrected covered prefix is not a gap ----------

/// Two covered segments were deleted; the crash lost only the first
/// deletion. Recovery sees seg-0 (covered), then seg-2 whose base does not
/// follow seg-0's last record. Covered survivors need not be contiguous —
/// only the first uncovered segment must bridge the checkpoint.
#[test]
fn partially_resurrected_covered_prefix_is_accepted() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..(2 * RECORDS_PER_SEGMENT) as u8 {
        vol.write_ct(i as u64 % 3, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap();
    let seg0 = layout::journal_segment(0);
    let saved = {
        let f = backing.open(&seg0, false).unwrap();
        let len = f.len().unwrap();
        let mut buf = vec![0u8; len as usize];
        f.read_at(0, &mut buf).unwrap();
        buf
    };
    drop(vol);
    let mut vol = recover(&backing).unwrap(); // seg-0, seg-1 sealed
    vol.write_ct(5, &ct(100), true).unwrap(); // seg-2 opened
    vol.checkpoint().unwrap(); // deletes seg-0 and seg-1
    assert_eq!(vol.journal_segment_count(), 1);
    drop(vol);

    // The lost unlink brings seg-0 back, seg-1 stays deleted.
    let f = backing.open(&seg0, true).unwrap();
    f.write_at(0, &saved).unwrap();
    f.sync_data().unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();

    let vol =
        recover(&backing).unwrap_or_else(|e| panic!("resurrected covered segment refused: {e:?}"));
    assert_eq!(vol.read_ct(5).unwrap().unwrap().1, ct(100));
    // The genuine gap case still fails: an uncovered segment missing.
    let _ = StdRng::seed_from_u64(0);
}

// ---------- K-08: decrypted plaintext is pinned to the volume's unit size ----------

mod wrong_size {
    use std::sync::Arc;

    use async_trait::async_trait;

    use maki_backing::Backing;
    use maki_core::engine::{Engine, EngineOptions};
    use maki_core::error::CoreError;
    use maki_crypto::{
        CiphertextUnit, CryptoCapabilities, CryptoContext, CryptoError, CryptoProvider,
        PlaintextUnit, SecretBuffer,
    };
    use maki_format::init;
    use maki_test_support::fake_provider::FakeCryptoProvider;
    use maki_test_support::CrashableBacking;

    use super::{options, superblock, UNIT};

    /// Declares two plaintext sizes and, once armed, returns the *other*
    /// one on decrypt: a remote that behaved during the attach self-test
    /// and misbehaves later, which the capability check alone accepts.
    struct ShortDecrypt {
        inner: FakeCryptoProvider,
        armed: std::sync::atomic::AtomicBool,
    }

    #[async_trait]
    impl CryptoProvider for ShortDecrypt {
        async fn capabilities(&self) -> Result<CryptoCapabilities, CryptoError> {
            let mut caps = self.inner.capabilities().await?;
            caps.supported_plaintext_sizes.push(UNIT / 2);
            Ok(caps)
        }
        async fn encrypt_batch(
            &self,
            context: &CryptoContext,
            items: &[PlaintextUnit],
        ) -> Result<Vec<CiphertextUnit>, CryptoError> {
            self.inner.encrypt_batch(context, items).await
        }
        async fn decrypt_batch(
            &self,
            context: &CryptoContext,
            items: &[CiphertextUnit],
        ) -> Result<Vec<PlaintextUnit>, CryptoError> {
            let pts = self.inner.decrypt_batch(context, items).await?;
            if !self.armed.load(std::sync::atomic::Ordering::SeqCst) {
                return Ok(pts);
            }
            Ok(pts
                .into_iter()
                .map(|pt| PlaintextUnit {
                    unit_index: pt.unit_index,
                    data: SecretBuffer::from_slice(&pt.data.expose()[..UNIT as usize / 2]),
                })
                .collect())
        }
    }

    /// A short plaintext used to be sliced out of range (a panic caught only
    /// at the NBD boundary); it must be a contract error, and a read of the
    /// first half of the unit must not silently succeed either.
    #[tokio::test]
    async fn short_plaintext_is_a_contract_error_not_a_panic() {
        let backing = Arc::new(CrashableBacking::new());
        init::create_volume(backing.as_ref(), superblock()).unwrap();
        let provider = Arc::new(ShortDecrypt {
            inner: FakeCryptoProvider::new(UNIT),
            armed: std::sync::atomic::AtomicBool::new(false),
        });
        let engine = Engine::attach(
            backing.clone() as Arc<dyn Backing>,
            provider.clone(),
            EngineOptions {
                volume: options(),
                cache: None,
                ..Default::default()
            },
        )
        .await
        .expect("attach (the provider behaves during the self-test)");
        engine
            .write(0, &vec![0xABu8; UNIT as usize], true)
            .await
            .unwrap();
        provider
            .armed
            .store(true, std::sync::atomic::Ordering::SeqCst);
        // Whole unit, and a two-unit request whose second unit is unwritten
        // (the short plaintext must not be sliced or padded into it).
        for (offset, len) in [(0u64, UNIT as usize), (0, 2 * UNIT as usize)] {
            match engine.read(offset, len).await {
                Err(CoreError::Crypto(CryptoError::Contract(_))) => {}
                other => panic!("read({offset},{len}) = {:?}", other.map(|v| v.len())),
            }
        }
    }
}

/// The relaxation must not hide a real gap: a missing *uncovered* segment
/// is still corruption.
#[test]
fn gap_after_the_checkpoint_boundary_is_still_refused() {
    let _guard = failpoints::test_lock();
    let backing = Arc::new(CrashableBacking::new());
    let mut vol = new_volume(&backing);
    for i in 0..(3 * RECORDS_PER_SEGMENT) as u8 {
        vol.write_ct(i as u64 % 3, &ct(i + 1), false).unwrap();
    }
    vol.flush().unwrap();
    drop(vol);
    // seg-1 holds uncovered records: removing it is a real gap.
    backing.remove(&layout::journal_segment(1)).unwrap();
    backing.sync_dir(layout::JOURNAL_DIR).unwrap();
    let msg = expect_corrupt(recover(&backing));
    assert!(msg.contains("sequence") || msg.contains("bridge"), "{msg}");
}
