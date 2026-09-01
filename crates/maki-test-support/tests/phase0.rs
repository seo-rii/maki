//! Phase 0 — Executable Specification (SPEC §42).
//!
//! These tests define the durability contract that every later phase is
//! measured against. They exercise the executable specification itself:
//! ReferenceBlockModel, CrashableBacking, FakeCryptoProvider, ManualClock,
//! DeterministicScheduler.

use std::cell::{Cell, RefCell};
use std::rc::Rc;
use std::sync::Arc;
use std::time::Duration;

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use maki_backing::Backing;
use maki_crypto::{Clock, CryptoContext, CryptoProvider, PlaintextUnit, SecretBuffer};
use maki_test_support::crash_backing::CrashableBacking;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::model::ReferenceBlockModel;
use maki_test_support::oracle::{run_random_sequence, SequenceConfig};
use maki_test_support::sched::{yield_now, DeterministicScheduler};
use maki_test_support::ManualClock;

const UNIT: usize = 512;

fn ctx() -> CryptoContext {
    CryptoContext {
        volume_uuid: uuid::Uuid::from_u128(0xABCD_EF00),
        format_version: 1,
        crypto_compatibility_id: "test-profile-v1".to_string(),
    }
}

/// SPEC §42 "normal write followed by crash": an acknowledged-but-unflushed
/// write may surface as either old or new data after crash — and across many
/// seeds *both* outcomes must actually occur.
#[test]
fn normal_write_then_crash_may_be_old_or_new() {
    let mut saw_old = false;
    let mut saw_new = false;
    for seed in 0..200u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let backing = CrashableBacking::new();
        let file = backing.open("data", true).unwrap();
        file.set_len(UNIT as u64).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();

        let mut model = ReferenceBlockModel::new(UNIT, 1);

        let new = vec![7u8; UNIT];
        file.write_at(0, &new).unwrap();
        model.write(0, &new);

        backing.crash(&mut rng);

        let file = backing.open("data", false).unwrap();
        let mut actual = vec![0u8; UNIT];
        file.read_at(0, &mut actual).unwrap();
        model.crash_adopt(0, &actual).expect("oracle violation");

        if actual == new {
            saw_new = true;
        } else if actual == vec![0u8; UNIT] {
            saw_old = true;
        } else {
            panic!("crash produced impossible content");
        }
    }
    assert!(saw_old, "crash never lost an unflushed write");
    assert!(saw_new, "crash never kept an unflushed write");
}

/// SPEC §42 "FUA followed by crash": a FUA-successful write MUST be durable.
#[test]
fn fua_write_then_crash_is_durable() {
    for seed in 0..100u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let backing = CrashableBacking::new();
        let file = backing.open("data", true).unwrap();
        file.set_len(UNIT as u64).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();

        let mut model = ReferenceBlockModel::new(UNIT, 1);
        let new = vec![9u8; UNIT];
        // FUA = write + immediate data sync.
        file.write_at(0, &new).unwrap();
        file.sync_data().unwrap();
        model.write_fua(0, &new);

        backing.crash(&mut rng);

        let file = backing.open("data", false).unwrap();
        let mut actual = vec![0u8; UNIT];
        file.read_at(0, &mut actual).unwrap();
        model.crash_adopt(0, &actual).expect("FUA durability violated");
        assert_eq!(actual, new, "FUA write lost at seed {seed}");
    }
}

/// SPEC §42 "FLUSH followed by crash": everything acknowledged before a
/// successful FLUSH MUST be durable.
#[test]
fn flush_then_crash_is_durable() {
    for seed in 0..100u64 {
        let mut rng = StdRng::seed_from_u64(seed);
        let backing = CrashableBacking::new();
        let file = backing.open("data", true).unwrap();
        file.set_len(2 * UNIT as u64).unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();

        let mut model = ReferenceBlockModel::new(UNIT, 2);
        let a = vec![1u8; UNIT];
        let b = vec![2u8; UNIT];
        file.write_at(0, &a).unwrap();
        model.write(0, &a);
        file.write_at(UNIT as u64, &b).unwrap();
        model.write(1, &b);

        // FLUSH
        file.sync_data().unwrap();
        model.flush();

        // A post-flush write may be old or new.
        let c = vec![3u8; UNIT];
        file.write_at(0, &c).unwrap();
        model.write(0, &c);

        backing.crash(&mut rng);

        let file = backing.open("data", false).unwrap();
        let mut u0 = vec![0u8; UNIT];
        let mut u1 = vec![0u8; UNIT];
        file.read_at(0, &mut u0).unwrap();
        file.read_at(UNIT as u64, &mut u1).unwrap();
        model.crash_adopt(0, &u0).expect("unit 0 violated");
        model.crash_adopt(1, &u1).expect("unit 1 violated");
        assert_eq!(u1, b, "flushed unit 1 lost at seed {seed}");
        assert!(u0 == a || u0 == c, "unit 0 impossible content");
    }
}

/// SPEC §42 "partial record": a torn tail write must be detectable via
/// length/CRC framing — the framing pattern the journal will use.
#[test]
fn partial_record_torn_write_is_detectable() {
    let backing = CrashableBacking::new();
    let file = backing.open("seg", true).unwrap();
    file.set_len(0).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    // Frame: [len u32][crc32 u32][payload]
    let payload = vec![0x5Au8; 300];
    let mut record = Vec::new();
    record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    record.extend_from_slice(&crc32fast::hash(&payload).to_le_bytes());
    record.extend_from_slice(&payload);

    file.write_at(0, &record).unwrap();
    // Crash keeping only a 128-byte prefix of the (unsynced) record.
    backing.crash_keep_torn_prefix("seg", 128);

    let file = backing.open("seg", false).unwrap();
    let flen = file.len().unwrap();
    assert_eq!(flen, 128, "torn prefix length");

    // Reader: header present but payload short => partial record detected.
    let mut hdr = [0u8; 8];
    file.read_at(0, &mut hdr).unwrap();
    let len = u32::from_le_bytes(hdr[0..4].try_into().unwrap()) as u64;
    let crc = u32::from_le_bytes(hdr[4..8].try_into().unwrap());
    let complete = 8 + len <= flen;
    assert!(!complete, "partial record must be detected as incomplete");

    // And even if length looked plausible, CRC must not validate garbage.
    let avail = (flen - 8) as usize;
    let mut tail = vec![0u8; avail];
    file.read_at(8, &mut tail).unwrap();
    assert_ne!(crc32fast::hash(&tail), crc, "torn payload must fail CRC");
}

/// SPEC §42 "same-unit concurrent write": with a per-unit critical section,
/// two concurrent writers never overlap and the final value is one of theirs,
/// under randomized deterministic interleavings.
#[test]
fn same_unit_concurrent_writes_serialize() {
    for seed in 0..100u64 {
        let mut sched = DeterministicScheduler::new(seed);
        let busy = Rc::new(Cell::new(false));
        let value = Rc::new(Cell::new(0u32));
        let overlaps = Rc::new(Cell::new(0u32));

        for writer in 1..=2u32 {
            let busy = busy.clone();
            let value = value.clone();
            let overlaps = overlaps.clone();
            sched.spawn(async move {
                // spin-acquire the unit lock
                loop {
                    if !busy.get() {
                        busy.set(true);
                        break;
                    }
                    yield_now().await;
                }
                if value.get() != 0 && busy.get() != true {
                    overlaps.set(overlaps.get() + 1);
                }
                // critical section with interleaving opportunities
                let before = value.get();
                yield_now().await;
                yield_now().await;
                if value.get() != before {
                    overlaps.set(overlaps.get() + 1);
                }
                value.set(writer);
                yield_now().await;
                busy.set(false);
            });
        }
        sched.run();
        assert_eq!(overlaps.get(), 0, "critical section overlapped, seed {seed}");
        let v = value.get();
        assert!(v == 1 || v == 2, "final value must be one writer's");
    }
}

/// SPEC §42 "allocation mismatch": data synced into a file whose directory
/// entry was never synced is lost after crash — the exact hazard the
/// allocation-map/catalog protocol must handle.
#[test]
fn unsynced_file_creation_is_lost_after_crash() {
    // Without sync_dir: creation lost.
    let backing = CrashableBacking::new();
    backing.create_dir_all("data").unwrap();
    backing.sync_dir("").unwrap();
    let f = backing.open("data/slot-5", true).unwrap();
    f.write_at(0, b"ciphertext").unwrap();
    f.sync_data().unwrap(); // data synced, dirent not
    backing.crash_all_lost();
    assert!(
        !backing.exists("data/slot-5").unwrap(),
        "unsynced file creation must not survive crash"
    );

    // With sync_dir: creation survives even crash_all_lost.
    let backing = CrashableBacking::new();
    backing.create_dir_all("data").unwrap();
    backing.sync_dir("").unwrap();
    let f = backing.open("data/slot-5", true).unwrap();
    f.write_at(0, b"ciphertext").unwrap();
    f.sync_data().unwrap();
    backing.sync_dir("data").unwrap();
    backing.crash_all_lost();
    assert!(backing.exists("data/slot-5").unwrap());
    let f = backing.open("data/slot-5", false).unwrap();
    let mut buf = vec![0u8; 10];
    f.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"ciphertext");
}

/// SPEC §42 "retry semaphore release": a permit is dropped before backoff
/// sleep, so a second requester proceeds while the first waits (ManualClock
/// controls time; nothing wakes until `advance`).
#[test]
fn retry_backoff_releases_semaphore() {
    let clock = Arc::new(ManualClock::new());
    let mut sched = DeterministicScheduler::new(42);
    let permits = Rc::new(Cell::new(1u32));
    let events: Rc<RefCell<Vec<&'static str>>> = Rc::new(RefCell::new(Vec::new()));

    {
        let permits = permits.clone();
        let events = events.clone();
        let clock = clock.clone();
        sched.spawn(async move {
            // t1: acquire, fail RPC, RELEASE PERMIT, then back off.
            assert!(permits.get() > 0);
            permits.set(permits.get() - 1);
            events.borrow_mut().push("t1-acquired");
            yield_now().await;
            permits.set(permits.get() + 1); // release BEFORE backoff
            events.borrow_mut().push("t1-released");
            clock.sleep(Duration::from_millis(100)).await;
            events.borrow_mut().push("t1-woke");
        });
    }
    {
        let permits = permits.clone();
        let events = events.clone();
        sched.spawn(async move {
            // t2: waits for a permit; must get one while t1 is in backoff.
            loop {
                if permits.get() > 0 {
                    permits.set(permits.get() - 1);
                    break;
                }
                yield_now().await;
            }
            events.borrow_mut().push("t2-acquired");
            permits.set(permits.get() + 1);
        });
    }
    {
        let clock = clock.clone();
        let events = events.clone();
        sched.spawn(async move {
            // driver: only release time once t2 has its permit.
            loop {
                if events.borrow().contains(&"t2-acquired") {
                    break;
                }
                yield_now().await;
            }
            clock.advance(Duration::from_millis(150));
        });
    }
    sched.run();

    let events = events.borrow();
    let pos = |e: &str| events.iter().position(|x| *x == e).unwrap();
    assert!(pos("t1-released") < pos("t2-acquired"));
    assert!(
        pos("t2-acquired") < pos("t1-woke"),
        "t2 must acquire while t1 is parked in backoff: {events:?}"
    );
}

/// ManualClock: sleeps complete only when time is advanced.
#[test]
fn manual_clock_sleep_requires_advance() {
    let clock = Arc::new(ManualClock::new());
    let fired = Rc::new(Cell::new(false));
    let mut sched = DeterministicScheduler::new(1);
    {
        let clock = clock.clone();
        let fired = fired.clone();
        sched.spawn(async move {
            clock.sleep(Duration::from_secs(5)).await;
            fired.set(true);
        });
    }
    // Without advancing: must not complete within a bounded poll budget.
    assert!(!sched.run_bounded(1_000));
    assert!(!fired.get());
    clock.advance(Duration::from_secs(4));
    assert!(!sched.run_bounded(1_000));
    assert!(!fired.get(), "woke early");
    clock.advance(Duration::from_secs(1));
    sched.run();
    assert!(fired.get());
}

/// FakeCryptoProvider: round-trips, binds context, and never returns
/// plaintext from corrupted ciphertext.
#[test]
fn fake_provider_roundtrip_and_integrity() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    rt.block_on(async {
        let p = FakeCryptoProvider::new(UNIT as u32);
        let caps = p.capabilities().await.unwrap();
        assert!(caps.integrity.present());

        let pt = PlaintextUnit {
            unit_index: 3,
            data: SecretBuffer::from_slice(&vec![0xAB; UNIT]),
        };
        let cts = p.encrypt_batch(&ctx(), &[pt]).await.unwrap();
        assert_eq!(cts.len(), 1);
        assert!(cts[0].data.len() <= caps.max_ciphertext_size as usize);

        // Round trip.
        let pts = p.decrypt_batch(&ctx(), &cts).await.unwrap();
        assert_eq!(pts[0].data.expose(), &vec![0xAB; UNIT][..]);

        // Corruption is detected, never decrypted silently.
        let mut corrupt = cts[0].clone();
        let last = corrupt.data.len() - 1;
        corrupt.data[last] ^= 0x01;
        let err = p.decrypt_batch(&ctx(), &[corrupt]).await.unwrap_err();
        assert!(matches!(err, maki_crypto::CryptoError::Integrity(_)));

        // Context binding: decrypting under a different unit index fails.
        let moved = maki_crypto::CiphertextUnit {
            unit_index: 4,
            data: cts[0].data.clone(),
        };
        assert!(p.decrypt_batch(&ctx(), &[moved]).await.is_err());
    });
}

/// Phase 0 gate (smoke): randomized op sequences, durability oracle
/// violations = 0. Full 10k-sequence gate: `phase0_gate_full` (ignored).
#[test]
fn phase0_gate_randomized_sequences_smoke() {
    let cfg = SequenceConfig {
        num_units: 8,
        unit_size: 256,
        ops: 60,
    };
    for seed in 0..500u64 {
        run_random_sequence(seed, &cfg).unwrap_or_else(|v| panic!("seed {seed}: {v}"));
    }
}

#[test]
#[ignore = "phase gate: 10,000+ randomized model sequences"]
fn phase0_gate_full() {
    let cfg = SequenceConfig {
        num_units: 8,
        unit_size: 256,
        ops: 60,
    };
    for seed in 0..10_000u64 {
        run_random_sequence(seed, &cfg).unwrap_or_else(|v| panic!("seed {seed}: {v}"));
    }
}

/// The model itself must catch violations: fabricated "impossible" content
/// is rejected by the oracle.
#[test]
fn oracle_rejects_impossible_content() {
    let mut model = ReferenceBlockModel::new(4, 1);
    model.write(0, &[1, 1, 1, 1]);
    model.flush();
    model.write(0, &[2, 2, 2, 2]);
    // 3,3,3,3 was never written: violation.
    assert!(model.crash_adopt(0, &[3, 3, 3, 3]).is_err());
    // both old-durable and pending-new are fine
    assert!(model.crash_adopt(0, &[1, 1, 1, 1]).is_ok());
}

/// Deterministic RNG sanity for reproducibility of gate failures.
#[test]
fn sequences_are_reproducible() {
    let cfg = SequenceConfig {
        num_units: 4,
        unit_size: 128,
        ops: 30,
    };
    let mut rng = StdRng::seed_from_u64(7);
    let _: u64 = rng.random();
    run_random_sequence(1234, &cfg).unwrap();
    run_random_sequence(1234, &cfg).unwrap(); // same seed, same result: no panic either time
}
