//! Audit round 4 (rollback-witness): the local freshness authority
//! (`StateStore`, #189's stage/commit split) under failed writeback and
//! power loss. Not part of the maintained suite.
//!
//! The store runs on a `CrashableBacking` process view with tearing. Every
//! `fdatasync`, directory sync and rename may fail (Linux semantics for a
//! failed `fdatasync`: dirty pages are marked clean with unknown
//! persistence, a bare retry writes nothing). A failure before the rename
//! must fail only its request and leave the store usable; a later
//! successful request must still be durable. After any error the store may
//! be poisoned (reopen required). Oracle: after a power loss, or a restart
//! after a poison, the reopened record is exactly the last acknowledged one,
//! or the record of the one request whose outcome was unknown.

#![cfg(target_os = "linux")]

use std::io;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use parking_lot::Mutex;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use uuid::Uuid;

use maki_backing::remote_witness::{
    namespace, Action, Descriptor, Phase, Record, Request, Role, SessionAuthorization, StateStore,
};
use maki_backing::witness::Anchor;
use maki_backing::Backing;
use maki_test_support::crash_backing::FaultOp;
use maki_test_support::CrashableBacking;

const IDENTITY: [u8; 16] = [5; 16];

fn next_request(rng: &mut StdRng, acked: &Record, auth: &mut SessionAuthorization) -> Request {
    let action = match acked.phase {
        Phase::Released => {
            *auth = SessionAuthorization::generate().unwrap();
            Action::Claim
        }
        Phase::Claimed => {
            let (anchor, epoch) = match &acked.current {
                Some(current) => (current.anchor.clone(), current.epoch),
                None => (
                    Anchor {
                        identity: IDENTITY,
                        generation: 0,
                        root: [1; 32],
                    },
                    0,
                ),
            };
            Action::Activate {
                descriptor: Descriptor {
                    anchor,
                    epoch,
                    namespace: namespace(acked.fence, acked.session),
                },
            }
        }
        Phase::Active if rng.random_bool(0.85) => {
            let current = acked.current.as_ref().unwrap();
            let mut root = [0u8; 32];
            rng.fill(&mut root);
            Action::Advance {
                anchor: Anchor {
                    identity: IDENTITY,
                    generation: current.anchor.generation + 1,
                    root,
                },
            }
        }
        _ => Action::Release,
    };
    Request {
        operation_id: *Uuid::new_v4().as_bytes(),
        expected: Some(acked.clone()),
        action,
        authorization: Some(auth.clone()),
    }
}

fn inspect(store: &mut StateStore) -> io::Result<Record> {
    store.handle(
        Role::Writer,
        &Request {
            operation_id: *Uuid::new_v4().as_bytes(),
            expected: None,
            action: Action::Inspect,
            authorization: None,
        },
    )
}

fn run(seed: u64, steps: usize, stats: &mut [u64; 6]) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed ^ 0xF01);
    let machine = CrashableBacking::new().with_tearing(64);
    let mut store =
        StateStore::create_backing(machine.process() as Arc<dyn Backing>, IDENTITY).unwrap();
    let mut acked = inspect(&mut store).unwrap();
    let permille = Arc::new(AtomicU32::new(0));
    let hook_rng = Arc::new(Mutex::new(StdRng::seed_from_u64(seed ^ 0x77)));
    {
        let permille = permille.clone();
        let hook_rng = hook_rng.clone();
        machine.set_fault_hook(Some(Arc::new(move |op: &FaultOp<'_>| {
            let p = permille.load(Ordering::SeqCst);
            let eligible = matches!(
                op,
                FaultOp::SyncData { .. }
                    | FaultOp::SyncDir { .. }
                    | FaultOp::Rename { .. }
                    | FaultOp::WriteAt { .. }
            );
            (eligible && p > 0 && hook_rng.lock().random_range(0..1000) < p)
                .then(|| io::Error::from_raw_os_error(5))
        })));
    }
    let mut auth = SessionAuthorization::generate().unwrap();
    let mut log = Vec::new();
    // The record of the one request whose outcome is unknown.
    let mut uncertain: Option<Record> = None;
    for step in 0..steps {
        let faulty = rng.random_bool(0.5);
        permille.store(if faulty { 250 } else { 0 }, Ordering::SeqCst);
        let roll = rng.random_range(0..100);
        if roll < 8 || uncertain.is_some() && roll < 30 {
            // Power loss (or, after a poison, sometimes a plain restart).
            permille.store(0, Ordering::SeqCst);
            drop(store);
            let power = uncertain.is_none() || rng.random_bool(0.6);
            if power {
                if rng.random_bool(0.3) {
                    machine.crash_all_lost();
                } else {
                    machine.crash(&mut rng);
                }
                stats[0] += 1;
            } else {
                stats[1] += 1;
            }
            // A reopen may itself fail to publish; retry it.
            let mut reopened = None;
            for attempt in 0..6 {
                permille.store(
                    if attempt < 4 && rng.random_bool(0.4) {
                        300
                    } else {
                        0
                    },
                    Ordering::SeqCst,
                );
                match StateStore::open_backing(machine.process() as Arc<dyn Backing>) {
                    Ok(s) => {
                        reopened = Some(s);
                        break;
                    }
                    Err(e) => {
                        log.push(format!("{step}: reopen attempt {attempt} -> {e}"));
                        stats[2] += 1;
                        if rng.random_bool(0.3) {
                            // The witness host loses power again mid-recovery.
                            machine.crash(&mut rng);
                        }
                    }
                }
            }
            permille.store(0, Ordering::SeqCst);
            store = match reopened {
                Some(s) => s,
                None => {
                    return Err(format!(
                        "REOPEN-REFUSED seed {seed}\n  {}",
                        log[log.len().saturating_sub(30)..].join("\n  ")
                    ))
                }
            };
            let got = inspect(&mut store).map_err(|e| format!("INSPECT: {e}"))?;
            let ok = got == acked || uncertain.as_ref() == Some(&got);
            if !ok {
                return Err(format!(
                    "ACK-LOST seed {seed} step {step} ({}): reopened {got:?}\n  last acknowledged {acked:?}\n  uncertain {uncertain:?}\n  {}",
                    if power { "power loss" } else { "restart" },
                    log[log.len().saturating_sub(30)..].join("\n  ")
                ));
            }
            log.push(format!(
                "{step}: == {} -> {}",
                if power { "power loss" } else { "restart" },
                if got == acked { "acked" } else { "uncertain" }
            ));
            acked = got;
            uncertain = None;
            continue;
        }
        if uncertain.is_some() {
            // A poisoned store must refuse until reopened.
            match inspect(&mut store) {
                Ok(r) => {
                    // Not poisoned: the failure happened before the rename.
                    if r != acked {
                        return Err(format!(
                            "PRE-RENAME-FAILURE-CHANGED-STATE seed {seed} step {step}: {r:?}"
                        ));
                    }
                    uncertain = None;
                }
                Err(_) => continue,
            }
        }
        let request = next_request(&mut rng, &acked, &mut auth);
        let label = format!("{:?}", std::mem::discriminant(&request.action));
        match store.handle(Role::Writer, &request) {
            Ok(record) => {
                if record.last_operation != request.operation_id {
                    return Err(format!("REPLY-MISMATCH seed {seed} step {step}"));
                }
                log.push(format!("{step}: {label} -> ok"));
                acked = record;
                stats[3] += 1;
            }
            Err(e) => {
                log.push(format!("{step}: {label} -> ERR {e}"));
                stats[4] += 1;
                // Outcome unknown until the store is reopened, unless the
                // store still answers (the failure preceded the rename).
                uncertain = Some(predict(&acked, &request).unwrap());
                permille.store(0, Ordering::SeqCst);
                match inspect(&mut store) {
                    Ok(r) if r == acked => {
                        // Not poisoned: a pre-rename failure. The retry of
                        // the same request must now succeed and be durable.
                        stats[5] += 1;
                        uncertain = None;
                        match store.handle(Role::Writer, &request) {
                            Ok(record) => acked = record,
                            Err(e) => {
                                log.push(format!("{step}: retry -> ERR {e}"));
                                uncertain = Some(predict(&acked, &request).unwrap());
                            }
                        }
                    }
                    Ok(r) => {
                        return Err(format!(
                            "FAILED-REQUEST-VISIBLE seed {seed} step {step}: {r:?}"
                        ))
                    }
                    Err(_) => {}
                }
            }
        }
    }
    Ok(())
}

/// The record a request produces from `acked`, mirroring `transition` for
/// the four actions this driver issues.
fn predict(acked: &Record, request: &Request) -> Option<Record> {
    let mut next = acked.clone();
    match &request.action {
        Action::Claim => {
            next.fence += 1;
            next.session = request.operation_id;
            next.phase = Phase::Claimed;
            next.restore_source = None;
        }
        Action::Activate { descriptor } => {
            next.current = Some(descriptor.clone());
            next.phase = Phase::Active;
        }
        Action::Advance { anchor } => {
            next.current.as_mut()?.anchor = anchor.clone();
        }
        Action::Release => next.phase = Phase::Released,
        _ => return None,
    }
    next.last_operation = request.operation_id;
    Some(next)
}

#[test]
fn audit4_local_authority_survives_failed_writeback_and_power_loss() {
    let seeds: u64 = std::env::var("AUDIT_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut stats = [0u64; 6];
    let mut failures = Vec::new();
    for seed in 0..seeds {
        if let Err(t) = run(seed, 200, &mut stats) {
            println!(
                "AUDIT-FAIL seed={seed} class={}",
                t.split(' ').next().unwrap_or("?")
            );
            failures.push(t);
        }
    }
    println!(
        "AUDIT-WITNESS-STORE seeds={seeds} failures={} power_losses={} restarts={} reopen_failures={} acks={} errors={} pre_rename_failures={}",
        failures.len(),
        stats[0],
        stats[1],
        stats[2],
        stats[3],
        stats[4],
        stats[5]
    );
    if let Some(first) = failures.first() {
        panic!("{} failure(s); first:\n{first}", failures.len());
    }
}
