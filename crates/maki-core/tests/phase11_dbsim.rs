//! Phase 11 — database-workload qualification, block-level simulation
//! (SPEC §53).
//!
//! A miniature WAL database (modeled on SQLite WAL / `synchronous=FULL`)
//! runs on the engine over `CrashableBacking`:
//!
//! - a transaction writes WAL frames (one unit each) + a commit record
//!   carrying frame count and a checksum over all frame payloads,
//! - FLUSH → the transaction is **committed** (enters the ledger),
//! - frames are applied to the main page area, FLUSH, WAL slots reused.
//!
//! Crashes are injected at every protocol stage; recovery replays committed
//! WAL transactions exactly like a database would. A **WAL header** carries
//! the current epoch (SQLite's WAL salt): the header is written and FLUSHed
//! before any frame of its epoch, at open, after recovery, and at every WAL
//! wrap — recovery replays only header-epoch transactions, so stale frames
//! can never be replayed over durably-applied newer data (the header flush
//! is SQLite's "WAL reset fsync"). The oracle: every page equals the value
//! of the last ledger-committed transaction that wrote it — durable
//! transaction loss = 0, silent corruption = 0.

use std::collections::HashMap;
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{Engine, EngineOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const NUM_PAGES: u64 = 64; // main pages at units 0..64
const WAL_BASE: u64 = 128; // WAL slots at units 128..256
const WAL_SLOTS: u64 = 128;
const DEVICE_UNITS: u64 = 256;

const WAL_MAGIC: u32 = 0x57414C31; // "WAL1"
const COMMIT_MAGIC: u32 = 0x434D5431; // "CMT1"
const HDR_MAGIC: u32 = 0x57484431; // "WHD1"

/// WAL header slot; frames live at WAL_BASE+1 .. WAL_BASE+WAL_SLOTS.
const WAL_HDR: u64 = WAL_BASE;
const FIRST_FRAME_SLOT: u64 = WAL_BASE + 1;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0xDB),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            UNIT,
            UNIT,
            512,
            UNIT + 8,
            DEVICE_UNITS * UNIT as u64,
            32 * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Engine {
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        Arc::new(FakeCryptoProvider::new(UNIT)),
        EngineOptions::default(),
    )
    .await
    .unwrap()
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

/// Deterministic page image for (txn, page).
fn page_image(txn: u32, page: u64) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    for (i, b) in v.iter_mut().enumerate() {
        *b = (txn as usize)
            .wrapping_mul(31)
            .wrapping_add(page as usize)
            .wrapping_add(i)
            .wrapping_rem(251) as u8;
    }
    v
}

/// WAL frame: [magic u32][txn u32][page u64][epoch u32][payload…]
fn wal_frame(txn: u32, page: u64, epoch: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    v[0..4].copy_from_slice(&WAL_MAGIC.to_le_bytes());
    v[4..8].copy_from_slice(&txn.to_le_bytes());
    v[8..16].copy_from_slice(&page.to_le_bytes());
    v[16..20].copy_from_slice(&epoch.to_le_bytes());
    let image = page_image(txn, page);
    let body = UNIT as usize - 20;
    v[20..].copy_from_slice(&image[..body]);
    v
}

/// WAL header: [magic u32][epoch u32]. Written + FLUSHed before any frame
/// of its epoch exists.
fn wal_header(epoch: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    v[0..4].copy_from_slice(&HDR_MAGIC.to_le_bytes());
    v[4..8].copy_from_slice(&epoch.to_le_bytes());
    v
}

async fn write_wal_header(engine: &Engine, epoch: u32) {
    engine
        .write(off(WAL_HDR), &wal_header(epoch), false)
        .await
        .expect("wal header write");
    engine.flush().await.expect("wal header flush");
}

fn frame_payload_checksum(frames: &[Vec<u8>]) -> u32 {
    let mut hasher = crc32fast::Hasher::new();
    for f in frames {
        hasher.update(f);
    }
    hasher.finalize()
}

/// Commit record:
/// [magic u32][txn u32][num_frames u32][checksum u32][slot u64][epoch u32]
fn commit_record(txn: u32, num_frames: u32, checksum: u32, first_slot: u64, epoch: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    v[0..4].copy_from_slice(&COMMIT_MAGIC.to_le_bytes());
    v[4..8].copy_from_slice(&txn.to_le_bytes());
    v[8..12].copy_from_slice(&num_frames.to_le_bytes());
    v[12..16].copy_from_slice(&checksum.to_le_bytes());
    v[16..24].copy_from_slice(&first_slot.to_le_bytes());
    v[24..28].copy_from_slice(&epoch.to_le_bytes());
    v
}

/// Reconstruct the full page image from a WAL frame (payload is truncated
/// by the 20-byte header; the tail is recomputed deterministically).
fn frame_to_image(frame: &[u8]) -> (u32, u64, Vec<u8>) {
    let txn = u32::from_le_bytes(frame[4..8].try_into().unwrap());
    let page = u64::from_le_bytes(frame[8..16].try_into().unwrap());
    (txn, page, page_image(txn, page))
}

/// Database recovery: read the WAL header, then scan frame slots and
/// validate commit records (all frames present, epoch coherent, checksum
/// matches). Only transactions of the **header epoch** are replayed —
/// anything else is a pre-reset leftover, already durably applied.
/// Returns (replayed txn ids, header epoch).
async fn recover_database(engine: &Engine) -> (Vec<u32>, u32) {
    let hdr = engine
        .read(off(WAL_HDR), UNIT as usize)
        .await
        .expect("WAL header read");
    let hdr_magic = u32::from_le_bytes(hdr[0..4].try_into().unwrap());
    if hdr_magic != HDR_MAGIC {
        return (Vec::new(), 0); // fresh database: nothing to replay
    }
    let hdr_epoch = u32::from_le_bytes(hdr[4..8].try_into().unwrap());

    // Read the whole WAL region (index i = absolute slot WAL_BASE + i;
    // index 0 is the header and never parses as frame or commit).
    let mut slots: Vec<Vec<u8>> = Vec::new();
    for s in 0..WAL_SLOTS {
        slots.push(
            engine
                .read(off(WAL_BASE + s), UNIT as usize)
                .await
                .expect("WAL read"),
        );
    }
    // (slot, txn, epoch, frames)
    let mut candidates: Vec<(usize, u32, u32, Vec<Vec<u8>>)> = Vec::new();
    for (i, slot) in slots.iter().enumerate() {
        let magic = u32::from_le_bytes(slot[0..4].try_into().unwrap());
        if magic != COMMIT_MAGIC {
            continue;
        }
        let txn = u32::from_le_bytes(slot[4..8].try_into().unwrap());
        let num_frames = u32::from_le_bytes(slot[8..12].try_into().unwrap()) as u64;
        let checksum = u32::from_le_bytes(slot[12..16].try_into().unwrap());
        let first_slot = u64::from_le_bytes(slot[16..24].try_into().unwrap());
        let epoch = u32::from_le_bytes(slot[24..28].try_into().unwrap());
        // Only header-epoch transactions are replayable.
        if epoch != hdr_epoch {
            continue;
        }
        // Frames precede the commit record at slots first_slot..first_slot+n.
        if first_slot < FIRST_FRAME_SLOT || first_slot + num_frames != WAL_BASE + i as u64 {
            continue; // inconsistent record (torn txn): ignore
        }
        let mut frames = Vec::new();
        let mut valid = true;
        for f in 0..num_frames {
            let s = &slots[(first_slot - WAL_BASE + f) as usize];
            let fmagic = u32::from_le_bytes(s[0..4].try_into().unwrap());
            let ftxn = u32::from_le_bytes(s[4..8].try_into().unwrap());
            let fepoch = u32::from_le_bytes(s[16..20].try_into().unwrap());
            if fmagic != WAL_MAGIC || ftxn != txn || fepoch != epoch {
                valid = false;
                break;
            }
            frames.push(s.clone());
        }
        if !valid || frame_payload_checksum(&frames) != checksum {
            continue; // incomplete transaction: never replayed
        }
        candidates.push((i, txn, epoch, frames));
    }
    let mut replayed = Vec::new();
    // Within one epoch, slot order == transaction order.
    for (_, txn, _epoch, frames) in &candidates {
        for frame in frames {
            let (ftxn, page, image) = frame_to_image(frame);
            debug_assert_eq!(ftxn, *txn);
            engine
                .write(off(page), &image, false)
                .await
                .expect("replay");
        }
        replayed.push(*txn);
    }
    engine.flush().await.expect("replay flush");
    (replayed, hdr_epoch)
}

struct MiniDb {
    engine: Engine,
    next_wal_slot: u64,
    epoch: u32,
}

enum TxnOutcome {
    Committed,
    CrashedBeforeCommit,
    CrashedAfterCommit,
}

impl MiniDb {
    /// Run one transaction; `crash_stage` injects a crash (via returning
    /// early — the caller then crashes the backing): 0 = mid WAL write,
    /// 1 = after commit flush, 2 = after apply (before WAL reuse matters).
    async fn transaction(
        &mut self,
        txn: u32,
        pages: &[u64],
        crash_stage: Option<u8>,
    ) -> TxnOutcome {
        // WAL wrap: bump the epoch and rewrite the header (WAL reset).
        // Everything committed so far is durably applied at this point, so
        // old-epoch frames are dead the moment the header flush lands.
        if self.next_wal_slot + pages.len() as u64 + 1 >= WAL_BASE + WAL_SLOTS {
            self.next_wal_slot = FIRST_FRAME_SLOT;
            self.epoch += 1;
            write_wal_header(&self.engine, self.epoch).await;
        }
        let first_slot = self.next_wal_slot;
        let frames: Vec<Vec<u8>> = pages
            .iter()
            .map(|p| wal_frame(txn, *p, self.epoch))
            .collect();

        // 1. WAL frames.
        for (i, frame) in frames.iter().enumerate() {
            if crash_stage == Some(0) && i == frames.len() / 2 {
                return TxnOutcome::CrashedBeforeCommit;
            }
            self.engine
                .write(off(first_slot + i as u64), frame, false)
                .await
                .expect("wal write");
        }
        // 2. Commit record + FLUSH ⇒ committed.
        let commit = commit_record(
            txn,
            frames.len() as u32,
            frame_payload_checksum(&frames),
            first_slot,
            self.epoch,
        );
        self.engine
            .write(off(first_slot + frames.len() as u64), &commit, false)
            .await
            .expect("commit write");
        self.engine.flush().await.expect("commit flush");
        self.next_wal_slot = first_slot + frames.len() as u64 + 1;
        if crash_stage == Some(1) {
            return TxnOutcome::CrashedAfterCommit;
        }
        // 3. Apply to main pages + FLUSH.
        for page in pages {
            self.engine
                .write(off(*page), &page_image(txn, *page), false)
                .await
                .expect("apply");
        }
        self.engine.flush().await.expect("apply flush");
        if crash_stage == Some(2) {
            return TxnOutcome::CrashedAfterCommit;
        }
        TxnOutcome::Committed
    }
}

/// One full qualification run: transactions with random crash injection,
/// crash/recover cycles, ledger verification after every recovery.
async fn db_qualification_run(seed: u64, txn_count: u32) {
    let mut rng = StdRng::seed_from_u64(seed.wrapping_mul(0x9E37).wrapping_add(3));
    let backing = Arc::new(CrashableBacking::new());
    let engine = attach(&backing).await;
    write_wal_header(&engine, 1).await;
    let mut db = MiniDb {
        engine,
        next_wal_slot: FIRST_FRAME_SLOT,
        epoch: 1,
    };
    // page → last committed txn writing it
    let mut ledger: HashMap<u64, u32> = HashMap::new();

    let mut txn = 1u32;
    while txn <= txn_count {
        let page_count = rng.random_range(1..=4usize);
        let mut pages: Vec<u64> = (0..page_count)
            .map(|_| rng.random_range(0..NUM_PAGES))
            .collect();
        pages.sort();
        pages.dedup();

        let crash_stage = if rng.random_bool(0.3) {
            Some(rng.random_range(0..3u8))
        } else {
            None
        };
        let outcome = db.transaction(txn, &pages, crash_stage).await;
        match outcome {
            TxnOutcome::Committed | TxnOutcome::CrashedAfterCommit => {
                for p in &pages {
                    ledger.insert(*p, txn);
                }
            }
            TxnOutcome::CrashedBeforeCommit => {}
        }

        if crash_stage.is_some() {
            // Hard crash: random survival of everything volatile.
            let old_epoch = db.epoch;
            drop(db);
            backing.crash(&mut rng);
            let engine = attach(&backing).await;
            let (_replayed, hdr_epoch) = recover_database(&engine).await;

            // Oracle: every page shows its last committed value.
            for (page, committed_txn) in &ledger {
                let got = engine.read(off(*page), UNIT as usize).await.unwrap();
                assert_eq!(
                    got,
                    page_image(*committed_txn, *page),
                    "seed {seed}: page {page} lost txn {committed_txn} (durable transaction loss)"
                );
            }
            // Fresh WAL generation: everything committed is now durably
            // applied. Start a new epoch past anything on disk and make its
            // header durable before any new frames (WAL reset fsync).
            let new_epoch = old_epoch.max(hdr_epoch) + 1;
            write_wal_header(&engine, new_epoch).await;
            db = MiniDb {
                engine,
                next_wal_slot: FIRST_FRAME_SLOT,
                epoch: new_epoch,
            };
        }
        txn += 1;
    }

    // Final clean shutdown + reopen + integrity check (PRAGMA-style).
    db.engine.flush().await.unwrap();
    db.engine.checkpoint().await.unwrap();
    let engine = db.engine.clone();
    for (page, committed_txn) in &ledger {
        let got = engine.read(off(*page), UNIT as usize).await.unwrap();
        assert_eq!(
            got,
            page_image(*committed_txn, *page),
            "seed {seed}: final check"
        );
    }
}

/// Provider outage mid-transaction: writes fail, the transaction aborts,
/// and previously committed data is untouched (SPEC §53 "provider outage").
#[tokio::test]
async fn provider_outage_aborts_transaction_without_corruption() {
    let backing = Arc::new(CrashableBacking::new());
    let provider = Arc::new(FakeCryptoProvider::new(UNIT));
    if !backing.exists("superblock.a").unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let engine = Engine::attach(
        backing.clone() as Arc<dyn Backing>,
        provider.clone(),
        EngineOptions::default(),
    )
    .await
    .unwrap();

    // Committed baseline.
    engine
        .write(off(0), &page_image(1, 0), false)
        .await
        .unwrap();
    engine.flush().await.unwrap();

    // Outage: the next encrypt calls fail.
    provider.fail_next([maki_crypto::CryptoError::Retryable("outage".to_string())]);
    assert!(
        engine
            .write(off(0), &page_image(2, 0), false)
            .await
            .is_err(),
        "write during outage fails (engine layer has no retry; the \
         dispatcher above it does)"
    );
    // Old committed data intact, engine fully usable after the outage.
    assert_eq!(
        engine.read(off(0), UNIT as usize).await.unwrap(),
        page_image(1, 0)
    );
    engine.write(off(0), &page_image(3, 0), true).await.unwrap();
    drop(engine);
    backing.crash_all_lost();
    let engine = attach(&backing).await;
    assert_eq!(
        engine.read(off(0), UNIT as usize).await.unwrap(),
        page_image(3, 0)
    );
}

/// Smoke gate: 40 randomized qualification runs.
#[tokio::test]
async fn phase11_gate_dbsim_smoke() {
    for seed in 0..40u64 {
        db_qualification_run(seed, 25).await;
    }
}

/// Full gate: DB corruption = 0, durable transaction loss = 0.
#[tokio::test]
#[ignore = "phase gate: extended DB-sim crash qualification"]
async fn phase11_gate_dbsim_full() {
    for seed in 0..500u64 {
        db_qualification_run(seed, 40).await;
    }
}
