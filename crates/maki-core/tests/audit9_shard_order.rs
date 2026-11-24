//! Audit round 9 (r8-storage), item 3: the slot store now writes several
//! shards' metadata in ascending shard order (#388). The claim is that no
//! on-disk outcome depended on the order. Attack, not argument:
//!
//! - five shards, each given one of the states `SlotStore::open` treats
//!   differently (healthy, newest allocation copy lost so the older one is
//!   behind the slots, data file truncated by media damage, never-finished
//!   orphan), in EVERY assignment of states to shard indices, so ascending
//!   order visits the states in every relative order;
//! - then the first attach and the first writes after it (which store every
//!   loaded shard's map twice, the damage marks, the unproven sizes and the
//!   catalog), and a checkpoint;
//! - a fault at EVERY mutating backing operation of that phase: one
//!   transient failure (Linux failed-fsync model), a process death followed
//!   by a restart, and a process death followed by a power loss with torn
//!   writes (several samples) or with everything volatile lost;
//! - after every recovery each unit is compared with what was acknowledged:
//!   data stays data, a unit removed by the truncation stays EIO (never
//!   zeros, never data), a hole stays a hole; and what a recovery served is
//!   pinned by a worst-case power loss right after it.
//!
//! A second scenario cuts a live checkpoint that dirties the allocation (and,
//! with discard, the discard) maps of all shards at once.
//!
//! `AUDIT9_PERMS=all` runs all 60 assignments (default: 12 of them);
//! `AUDIT9_STEP=n` faults every n-th operation (default 1).

#![allow(clippy::await_holding_lock)]

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;

use rand::rngs::StdRng;
use rand::SeedableRng;
use uuid::Uuid;

use maki_backing::Backing;
use maki_core::engine::{AttachError, CheckpointPolicy, Engine, EngineOptions};
use maki_core::error::CoreError;
use maki_format::ab::AbStore;
use maki_format::allocation::AllocationMap;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::layout;
use maki_format::superblock::Superblock;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::fake_provider::FakeCryptoProvider;
use maki_test_support::CrashableBacking;

const UNIT: u32 = 512;
const PER: u64 = 8;
const SHARDS: u64 = 5;
const DEVICE_UNITS: u64 = SHARDS * PER;

#[derive(Clone, Copy, PartialEq, Eq, Debug, PartialOrd, Ord)]
enum Role {
    Healthy,
    Stale,
    Truncated,
    Orphan,
}

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x0A9_5EED),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(
            UNIT,
            UNIT,
            512,
            UNIT + 8,
            DEVICE_UNITS * UNIT as u64,
            PER * UNIT as u64,
        )
        .unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn options() -> EngineOptions {
    EngineOptions {
        checkpoint: CheckpointPolicy {
            emergency_reserve_bytes: 0,
            ..Default::default()
        },
        ..EngineOptions::default()
    }
}

async fn attach(backing: &Arc<CrashableBacking>) -> Result<Engine, AttachError> {
    Engine::attach(
        backing.process(),
        Arc::new(FakeCryptoProvider::new(UNIT)),
        options(),
    )
    .await
}

fn off(unit: u64) -> u64 {
    unit * UNIT as u64
}

fn image(unit: u64, stamp: u32) -> Vec<u8> {
    let mut v = vec![0u8; UNIT as usize];
    let seed = (unit as u32).wrapping_mul(0x9E37_79B1) ^ stamp.wrapping_mul(0x85EB_CA6B);
    for (i, b) in v.iter_mut().enumerate() {
        *b = (seed.wrapping_add(i as u32).wrapping_mul(0x2545_F491) >> 24) as u8;
    }
    v
}

// ---------------------------------------------------------------------------
// Fault injection: count mutating operations; fail one, or all from one on.

const COUNT: u8 = 0;
const ONCE: u8 = 1;
const DEAD: u8 = 2;

#[derive(Default)]
struct Inj {
    count: AtomicU64,
    at: AtomicI64,
    mode: AtomicU8,
    fired: AtomicBool,
}

impl Inj {
    fn arm(&self, mode: u8, at: i64) {
        self.count.store(0, Ordering::SeqCst);
        self.at.store(at, Ordering::SeqCst);
        self.mode.store(mode, Ordering::SeqCst);
        self.fired.store(false, Ordering::SeqCst);
    }
}

fn install(backing: &CrashableBacking, inj: &Arc<Inj>) {
    let inj = inj.clone();
    backing.set_fault_hook(Some(Arc::new(move |op| {
        let mutating = match op {
            FaultOp::Open { create, .. } => *create,
            _ => true,
        };
        if !mutating {
            return None;
        }
        let index = inj.count.fetch_add(1, Ordering::SeqCst) as i64;
        let at = inj.at.load(Ordering::SeqCst);
        let fail = match inj.mode.load(Ordering::SeqCst) {
            ONCE => index == at,
            DEAD => index >= at,
            _ => false,
        };
        if fail {
            inj.fired.store(true, Ordering::SeqCst);
            Some(io::Error::other(format!("injected at op {index}: {op:?}")))
        } else {
            None
        }
    })));
}

// ---------------------------------------------------------------------------
// What every unit may read as.

#[derive(Clone, Default)]
struct Expect {
    /// Acknowledged (FUA) data.
    data: BTreeMap<u64, Vec<u8>>,
    /// A write that was not acknowledged: its image may or may not be there.
    maybe: BTreeMap<u64, Vec<u8>>,
    /// Checkpointed data the truncation removed: EIO, never zeros or data.
    eio: BTreeSet<u64>,
    /// Never written, beyond the cut: EIO or a hole.
    eio_or_zero: BTreeSet<u64>,
}

fn is_eio(result: &Result<Vec<u8>, CoreError>) -> bool {
    matches!(result, Err(CoreError::Corrupt(_)) | Err(CoreError::Io(_)))
}

fn show(result: &Result<Vec<u8>, CoreError>) -> String {
    match result {
        Ok(bytes) if bytes.iter().all(|b| *b == 0) => "zeros".into(),
        Ok(bytes) => format!("data {:02x?}", &bytes[..6]),
        Err(e) => format!("error {e}"),
    }
}

/// Compare every unit; with `pin`, what was observed becomes the only
/// acceptable state from here on (a recovery served it).
async fn verify(engine: &Engine, expect: &mut Expect, pin: bool, what: &str) -> Result<(), String> {
    let zeros = vec![0u8; UNIT as usize];
    for unit in 0..DEVICE_UNITS {
        let result = engine.read(off(unit), UNIT as usize).await;
        let old_ok = |result: &Result<Vec<u8>, CoreError>| {
            if expect.eio.contains(&unit) {
                is_eio(result)
            } else if expect.eio_or_zero.contains(&unit) {
                is_eio(result) || result.as_ref().is_ok_and(|b| *b == zeros)
            } else {
                result.as_ref().is_ok_and(|b| *b == zeros)
            }
        };
        if let Some(want) = expect.data.get(&unit) {
            if result.as_ref().ok() != Some(want) {
                return Err(format!(
                    "{what}: unit {unit}: acknowledged data reads as {}",
                    show(&result)
                ));
            }
        } else if let Some(new) = expect.maybe.get(&unit).cloned() {
            if result.as_ref().ok() == Some(&new) {
                if pin {
                    expect.maybe.remove(&unit);
                    expect.eio.remove(&unit);
                    expect.eio_or_zero.remove(&unit);
                    expect.data.insert(unit, new);
                }
            } else if old_ok(&result) {
                if pin {
                    expect.maybe.remove(&unit);
                }
            } else {
                return Err(format!(
                    "{what}: unit {unit}: neither the unacknowledged write nor the state before \
                     it: {}",
                    show(&result)
                ));
            }
        } else if !old_ok(&result) {
            let wanted = if expect.eio.contains(&unit) {
                "EIO (checkpointed data removed by the truncation)"
            } else if expect.eio_or_zero.contains(&unit) {
                "EIO or zeros"
            } else {
                "zeros"
            };
            return Err(format!(
                "{what}: unit {unit}: wanted {wanted}, read {}",
                show(&result)
            ));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Scenario A: states at open, in every assignment to shard indices.

fn newest_alloc(backing: &CrashableBacking, shard: u64) -> String {
    let (a, b) = AbStore::new(layout::shard_alloc_a(shard), layout::shard_alloc_b(shard))
        .side_generations::<AllocationMap>(backing)
        .unwrap();
    assert!(a.is_some() && b.is_some(), "shard {shard}: {a:?} {b:?}");
    if a >= b {
        layout::shard_alloc_a(shard)
    } else {
        layout::shard_alloc_b(shard)
    }
}

/// Build the volume and return what it must read as.
async fn build(backing: &Arc<CrashableBacking>, roles: &[Role], discard: bool) -> Expect {
    let geometry = superblock().geometry;
    if discard {
        init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
    } else {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    let mut expect = Expect::default();
    let engine = attach(backing).await.unwrap();
    // Two checkpoints, so the two allocation copies of a shard differ: the
    // older lists the first unit only.
    for in_shard in [1u64, 5] {
        for (shard, role) in roles.iter().enumerate() {
            if *role != Role::Orphan {
                let unit = shard as u64 * PER + in_shard;
                engine.write(off(unit), &image(unit, 1), true).await.unwrap();
                expect.data.insert(unit, image(unit, 1));
            }
        }
        engine.checkpoint().await.unwrap();
    }
    drop(engine);
    backing.crash_all_lost();

    for (shard, role) in roles.iter().enumerate() {
        let shard = shard as u64;
        match role {
            Role::Healthy => {}
            Role::Stale | Role::Truncated => {
                let newest = newest_alloc(backing, shard);
                let file = backing.open(&newest, false).unwrap();
                file.set_len(file.len().unwrap() - 1).unwrap();
                file.sync_data().unwrap();
                if *role == Role::Truncated {
                    // Cut inside slot 4: slots 5..7 are gone.
                    let data = backing.open(&layout::shard_data(shard), false).unwrap();
                    data.set_len(geometry.slot_offset(4) + 447).unwrap();
                    data.sync_data().unwrap();
                    expect.data.remove(&(shard * PER + 5));
                    expect.eio.insert(shard * PER + 5);
                    expect.eio_or_zero.insert(shard * PER + 6);
                    expect.eio_or_zero.insert(shard * PER + 7);
                }
            }
            Role::Orphan => {
                if discard {
                    // A v3 shard's discard maps are stored and dir-synced
                    // before its data file is created.
                    let ab = AbStore::new(
                        layout::shard_discard_a(shard),
                        layout::shard_discard_b(shard),
                    )
                    .with_max_len(AllocationMap::encoded_len(PER));
                    let mut empty = AllocationMap::new(PER);
                    ab.store(backing.as_ref(), &mut empty).unwrap();
                    ab.store(backing.as_ref(), &mut empty).unwrap();
                    backing.sync_dir(layout::DATA_DIR).unwrap();
                }
                drop(backing.open(&layout::shard_data(shard), true).unwrap());
                backing.sync_dir(layout::DATA_DIR).unwrap();
            }
        }
    }
    expect
}

/// The phase under attack: attach, one write into every truncated shard
/// (beyond the cut) and every orphan, a checkpoint. Returns the engine if
/// the attach succeeded.
async fn target(
    backing: &Arc<CrashableBacking>,
    roles: &[Role],
    expect: &mut Expect,
    attach_tries: usize,
) -> Option<Engine> {
    let mut engine = None;
    for _ in 0..attach_tries {
        if let Ok(attached) = attach(backing).await {
            engine = Some(attached);
            break;
        }
    }
    let engine = engine?;
    for (shard, role) in roles.iter().enumerate() {
        let unit = match role {
            Role::Truncated => shard as u64 * PER + 6,
            Role::Orphan => shard as u64 * PER + 3,
            _ => continue,
        };
        match engine.write(off(unit), &image(unit, 2), true).await {
            Ok(()) => {
                expect.eio_or_zero.remove(&unit);
                expect.maybe.remove(&unit);
                expect.data.insert(unit, image(unit, 2));
            }
            Err(_) => {
                if !expect.data.contains_key(&unit) {
                    expect.maybe.insert(unit, image(unit, 2));
                }
            }
        }
    }
    for _ in 0..3 {
        if engine.checkpoint().await.is_ok() {
            break;
        }
    }
    Some(engine)
}

/// Everything recovery served must survive the worst power loss, and the
/// volume must take new writes into every damaged place.
async fn pin_and_heal(
    backing: &Arc<CrashableBacking>,
    expect: &mut Expect,
    what: &str,
) -> Result<(), String> {
    backing.crash_all_lost();
    let engine = attach(backing)
        .await
        .map_err(|e| format!("{what}: attach after the pinning power loss: {e}"))?;
    verify(&engine, expect, true, &format!("{what}, pinned")).await?;
    let rewrite: Vec<u64> = expect
        .eio
        .iter()
        .chain(&expect.eio_or_zero)
        .copied()
        .collect();
    for unit in rewrite {
        engine
            .write(off(unit), &image(unit, 3), true)
            .await
            .map_err(|e| format!("{what}: rewrite of unit {unit}: {e}"))?;
        expect.eio.remove(&unit);
        expect.eio_or_zero.remove(&unit);
        expect.data.insert(unit, image(unit, 3));
    }
    engine
        .checkpoint()
        .await
        .map_err(|e| format!("{what}: checkpoint after healing: {e}"))?;
    drop(engine);
    backing.crash_all_lost();
    let engine = attach(backing)
        .await
        .map_err(|e| format!("{what}: attach after healing: {e}"))?;
    verify(&engine, expect, true, &format!("{what}, healed")).await
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    Once,
    DeathRestart,
    DeathPowerLoss(u64),
    DeathAllLost,
}

async fn attack(roles: &[Role], discard: bool, at: i64, fault: Fault) -> Result<(), String> {
    let what = format!("roles {roles:?} discard={discard} op {at} {fault:?}");
    let backing = Arc::new(CrashableBacking::new().with_tearing(64));
    let mut expect = build(&backing, roles, discard).await;
    let inj = Arc::new(Inj::default());
    install(&backing, &inj);
    match fault {
        Fault::Once => {
            inj.arm(ONCE, at);
            let engine = target(&backing, roles, &mut expect, 4)
                .await
                .ok_or_else(|| format!("{what}: attach kept failing after one fault"))?;
            verify(&engine, &mut expect, false, &format!("{what}, live")).await?;
            // After the single fault everything works again.
            engine
                .flush()
                .await
                .map_err(|e| format!("{what}: flush after the fault: {e}"))?;
            engine
                .checkpoint()
                .await
                .map_err(|e| format!("{what}: checkpoint after the fault: {e}"))?;
            drop(engine);
            backing.set_fault_hook(None);
            let mut rng = StdRng::seed_from_u64(at as u64 ^ 0xA9A9);
            backing.crash(&mut rng);
        }
        Fault::DeathRestart | Fault::DeathPowerLoss(_) | Fault::DeathAllLost => {
            // A dead process's sync never ran.
            backing.set_lenient_sync_failures(true);
            inj.arm(DEAD, at);
            drop(target(&backing, roles, &mut expect, 1).await);
            backing.set_fault_hook(None);
            backing.set_lenient_sync_failures(false);
            match fault {
                Fault::DeathPowerLoss(seed) => {
                    let mut rng = StdRng::seed_from_u64(seed ^ (at as u64) << 8);
                    backing.crash(&mut rng);
                }
                Fault::DeathAllLost => backing.crash_all_lost(),
                _ => {}
            }
        }
    }
    let engine = attach(&backing)
        .await
        .map_err(|e| format!("{what}: recovery refused the volume: {e}"))?;
    verify(&engine, &mut expect, true, &format!("{what}, recovered")).await?;
    drop(engine);
    pin_and_heal(&backing, &mut expect, &what).await
}

fn permutations(items: &[Role]) -> Vec<Vec<Role>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = BTreeSet::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(i);
        for mut tail in permutations(&rest) {
            tail.insert(0, first);
            out.insert(tail);
        }
    }
    out.into_iter().collect()
}

fn env(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

async fn count_ops(roles: &[Role], discard: bool) -> i64 {
    let backing = Arc::new(CrashableBacking::new().with_tearing(64));
    let mut expect = build(&backing, roles, discard).await;
    let inj = Arc::new(Inj::default());
    install(&backing, &inj);
    inj.arm(COUNT, -1);
    let engine = target(&backing, roles, &mut expect, 1)
        .await
        .expect("undisturbed attach");
    verify(&engine, &mut expect, false, "undisturbed")
        .await
        .unwrap();
    let ops = inj.count.load(Ordering::SeqCst) as i64;
    drop(engine);
    backing.set_fault_hook(None);
    pin_and_heal(&backing, &mut expect, "undisturbed").await.unwrap();
    ops
}

async fn open_states(discard: bool) {
    let all = permutations(&[
        Role::Healthy,
        Role::Stale,
        Role::Truncated,
        Role::Orphan,
        Role::Orphan,
    ]);
    assert_eq!(all.len(), 60);
    let chosen: Vec<Vec<Role>> = if std::env::var("AUDIT9_PERMS").as_deref() == Ok("all") {
        all
    } else {
        all.into_iter().step_by(5).collect()
    };
    let step = env("AUDIT9_STEP", 1) as usize;
    let mut runs = 0u64;
    let mut failures = Vec::new();
    for roles in &chosen {
        let ops = count_ops(roles, discard).await;
        for at in (0..ops).step_by(step) {
            for fault in [
                Fault::Once,
                Fault::DeathRestart,
                Fault::DeathAllLost,
                Fault::DeathPowerLoss(1),
                Fault::DeathPowerLoss(2),
                Fault::DeathPowerLoss(3),
            ] {
                runs += 1;
                if let Err(violation) = attack(roles, discard, at, fault).await {
                    failures.push(violation);
                }
            }
        }
        println!(
            "AUDIT9-SHARD-ORDER discard={discard} roles {roles:?}: {ops} operations, {} failures so far, {runs} runs",
            failures.len()
        );
    }
    assert!(
        failures.is_empty(),
        "{} violation(s) in {runs} runs; first 5:\n{}",
        failures.len(),
        failures.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
    );
}

#[tokio::test]
async fn audit9_every_assignment_of_open_states_survives_a_fault_at_every_operation() {
    let _serial = maki_test_support::failpoints::test_lock();
    open_states(false).await;
}

#[tokio::test]
async fn audit9_every_assignment_of_open_states_with_discard_maps() {
    let _serial = maki_test_support::failpoints::test_lock();
    open_states(true).await;
}

// ---------------------------------------------------------------------------
// Scenario B: a live checkpoint that dirties every shard's maps at once.

async fn live_checkpoint(discard: bool) {
    let step = env("AUDIT9_STEP", 1) as usize;
    let mut runs = 0u64;
    let mut failures = Vec::new();
    let mut ops = None;
    let mut at = 0i64;
    loop {
        let faults: &[Option<Fault>] = if ops.is_none() {
            &[None]
        } else {
            &[
                Some(Fault::Once),
                Some(Fault::DeathRestart),
                Some(Fault::DeathAllLost),
                Some(Fault::DeathPowerLoss(1)),
                Some(Fault::DeathPowerLoss(2)),
                Some(Fault::DeathPowerLoss(3)),
                Some(Fault::DeathPowerLoss(4)),
            ]
        };
        for fault in faults {
            let what = format!("live checkpoint discard={discard} op {at} {fault:?}");
            let backing = Arc::new(CrashableBacking::new().with_tearing(64));
            if discard {
                init::create_volume_with_discard(backing.as_ref(), superblock()).unwrap();
            } else {
                init::create_volume(backing.as_ref(), superblock()).unwrap();
            }
            let mut expect = Expect::default();
            let engine = attach(&backing).await.unwrap();
            // Shards 0..3 exist and hold data; shard 4 is new in the
            // checkpoint under attack.
            for shard in 0..4u64 {
                for in_shard in [0u64, 2] {
                    let unit = shard * PER + in_shard;
                    engine.write(off(unit), &image(unit, 1), true).await.unwrap();
                    expect.data.insert(unit, image(unit, 1));
                }
            }
            engine.checkpoint().await.unwrap();
            for shard in 0..SHARDS {
                let unit = shard * PER + 4;
                engine.write(off(unit), &image(unit, 2), true).await.unwrap();
                expect.data.insert(unit, image(unit, 2));
                if discard && shard < 4 {
                    // Acknowledged trims of checkpointed data.
                    let trimmed = shard * PER + 2;
                    engine
                        .trim(off(trimmed), UNIT as usize, true)
                        .await
                        .unwrap();
                    expect.data.remove(&trimmed);
                }
            }
            let inj = Arc::new(Inj::default());
            install(&backing, &inj);
            match fault {
                None => {
                    inj.arm(COUNT, -1);
                    engine.checkpoint().await.unwrap();
                    ops = Some(inj.count.load(Ordering::SeqCst) as i64);
                    println!("AUDIT9-SHARD-ORDER live checkpoint discard={discard}: {} operations", ops.unwrap());
                    continue;
                }
                Some(Fault::Once) => {
                    inj.arm(ONCE, at);
                    let _ = engine.checkpoint().await;
                    if let Err(e) = verify(&engine, &mut expect, false, &format!("{what}, live")).await {
                        failures.push(e);
                        continue;
                    }
                    if let Err(e) = engine.checkpoint().await {
                        failures.push(format!("{what}: checkpoint after one fault: {e}"));
                        continue;
                    }
                    drop(engine);
                    backing.set_fault_hook(None);
                    let mut rng = StdRng::seed_from_u64(at as u64 ^ 0xB9B9);
                    backing.crash(&mut rng);
                }
                Some(fault) => {
                    backing.set_lenient_sync_failures(true);
                    inj.arm(DEAD, at);
                    let _ = engine.checkpoint().await;
                    drop(engine);
                    backing.set_fault_hook(None);
                    backing.set_lenient_sync_failures(false);
                    match fault {
                        Fault::DeathPowerLoss(seed) => {
                            let mut rng = StdRng::seed_from_u64(*seed ^ (at as u64) << 8);
                            backing.crash(&mut rng);
                        }
                        Fault::DeathAllLost => backing.crash_all_lost(),
                        _ => {}
                    }
                }
            }
            runs += 1;
            let result = async {
                let engine = attach(&backing)
                    .await
                    .map_err(|e| format!("{what}: recovery refused the volume: {e}"))?;
                verify(&engine, &mut expect, true, &format!("{what}, recovered")).await?;
                drop(engine);
                pin_and_heal(&backing, &mut expect, &what).await
            }
            .await;
            if let Err(e) = result {
                failures.push(e);
            }
        }
        if ops.is_some_and(|ops| at + step as i64 >= ops) {
            break;
        }
        if faults.len() > 1 {
            at += step as i64;
        }
    }
    assert!(
        failures.is_empty(),
        "{} violation(s) in {runs} runs; first 5:\n{}",
        failures.len(),
        failures.iter().take(5).cloned().collect::<Vec<_>>().join("\n")
    );
    println!("AUDIT9-SHARD-ORDER live checkpoint discard={discard}: {runs} runs, 0 violations");
}

#[tokio::test]
async fn audit9_a_checkpoint_over_every_shard_survives_a_fault_at_every_operation() {
    let _serial = maki_test_support::failpoints::test_lock();
    live_checkpoint(false).await;
}

#[tokio::test]
async fn audit9_a_checkpoint_over_every_shard_with_discard_maps() {
    let _serial = maki_test_support::failpoints::test_lock();
    live_checkpoint(true).await;
}
