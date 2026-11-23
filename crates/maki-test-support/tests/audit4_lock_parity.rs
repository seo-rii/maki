//! Audit round 4 (rollback-witness): randomized differential check of
//! `try_lock` identity semantics. Linux `flock` through `FileBacking` is the
//! ground truth: a lock belongs to the open file description, so it follows
//! the inode across rename, survives an unlink of its name, is not shared by
//! a recreated name, and is released when its handle closes. #292 (memory),
//! #319 (rollback) and #327 (crash model) each rebound their locks from path
//! names to file identities; this drives the same random sequences through
//! every backing (and the crash model through process views) and compares
//! each outcome with `FileBacking`'s. Not part of the maintained suite.

#![cfg(target_os = "linux")]

use std::io;
use std::sync::Arc;

use maki_backing::{Backing, FileBacking, MemBacking, RollbackBacking, VolumeLock};
use maki_test_support::CrashableBacking;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

const NAMES: [&str; 4] = ["a", "b", "d/c", "d/e"];

#[derive(Debug, PartialEq, Clone, Copy)]
enum Out {
    Ok,
    Busy,
    Missing,
    Other,
}

fn out<T>(r: &io::Result<T>) -> Out {
    match r {
        Ok(_) => Out::Ok,
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => Out::Busy,
        Err(e) if e.kind() == io::ErrorKind::NotFound => Out::Missing,
        Err(_) => Out::Other,
    }
}

struct Subject {
    name: &'static str,
    backing: Arc<dyn Backing>,
    locks: Vec<Option<Box<dyn VolumeLock>>>,
    files: Vec<Option<Arc<dyn maki_backing::BackingFile>>>,
    _dirs: Vec<tempfile::TempDir>,
}

fn subjects() -> Vec<Subject> {
    let file_root = tempfile::tempdir().unwrap();
    let rb_root = tempfile::tempdir().unwrap();
    let rb_witness = tempfile::tempdir_in("/dev/shm").unwrap();
    let crash = CrashableBacking::new();
    let view = crash.process();
    let rollback = RollbackBacking::create(rb_root.path(), rb_witness.path(), 16 * 4096).unwrap();
    vec![
        Subject {
            name: "FileBacking",
            backing: Arc::new(FileBacking::new(file_root.path()).unwrap()),
            locks: Vec::new(),
            files: Vec::new(),
            _dirs: vec![file_root],
        },
        Subject {
            name: "MemBacking",
            backing: Arc::new(MemBacking::new()),
            locks: Vec::new(),
            files: Vec::new(),
            _dirs: Vec::new(),
        },
        Subject {
            name: "CrashableBacking(process view)",
            backing: view,
            locks: Vec::new(),
            files: Vec::new(),
            _dirs: Vec::new(),
        },
        Subject {
            name: "RollbackBacking",
            backing: Arc::new(rollback),
            locks: Vec::new(),
            files: Vec::new(),
            _dirs: vec![rb_root, rb_witness],
        },
    ]
}

fn run(seed: u64, steps: usize) -> Result<(), String> {
    let mut rng = StdRng::seed_from_u64(seed);
    let mut subjects = subjects();
    let mut log = Vec::new();
    for step in 0..steps {
        let roll = rng.random_range(0..100);
        let a = NAMES[rng.random_range(0..NAMES.len())];
        let mut b = NAMES[rng.random_range(0..NAMES.len())];
        // Rename stays inside one directory (cross-directory renames are
        // backend-specific).
        if a.contains('/') != b.contains('/') {
            b = a;
        }
        let pick = rng.random::<u32>() as usize;
        let mut outcomes = Vec::new();
        let label;
        match roll {
            0..=29 => {
                label = format!("try_lock {a}");
                for s in &mut subjects {
                    let r = s.backing.try_lock(a);
                    outcomes.push(out(&r));
                    s.locks.push(r.ok());
                }
            }
            30..=44 => {
                label = format!("unlock #{}", pick % subjects[0].locks.len().max(1));
                for s in &mut subjects {
                    if !s.locks.is_empty() {
                        let i = pick % s.locks.len();
                        s.locks[i] = None;
                    }
                    outcomes.push(Out::Ok);
                }
            }
            45..=59 => {
                label = format!("rename {a} -> {b}");
                for s in &mut subjects {
                    outcomes.push(out(&s.backing.rename(a, b)));
                }
            }
            60..=71 => {
                label = format!("remove {a}");
                for s in &mut subjects {
                    outcomes.push(out(&s.backing.remove(a)));
                }
            }
            72..=81 => {
                label = format!("open {a} (create)");
                for s in &mut subjects {
                    let r = s.backing.open(a, true);
                    outcomes.push(out(&r));
                    s.files.push(r.ok());
                }
            }
            82..=87 => {
                label = "close a file".to_string();
                for s in &mut subjects {
                    if !s.files.is_empty() {
                        let i = pick % s.files.len();
                        s.files[i] = None;
                    }
                    outcomes.push(Out::Ok);
                }
            }
            88..=91 => {
                label = "mkdir d".to_string();
                for s in &mut subjects {
                    outcomes.push(out(&s.backing.create_dir_all("d")));
                }
            }
            _ => {
                label = "sync_dir".to_string();
                for s in &mut subjects {
                    let mut r = s.backing.sync_dir("");
                    if r.is_ok() && s.backing.exists("d").unwrap_or(false) {
                        r = s.backing.sync_dir("d");
                    }
                    outcomes.push(out(&r));
                }
            }
        }
        log.push(format!("{step}: {label} -> {outcomes:?}"));
        if outcomes.iter().any(|o| *o != outcomes[0]) {
            let detail: Vec<String> = subjects
                .iter()
                .zip(&outcomes)
                .map(|(s, o)| format!("{}={o:?}", s.name))
                .collect();
            let tail = log.len().saturating_sub(40);
            return Err(format!(
                "LOCK-PARITY seed {seed} step {step}: {label}: {}\n  {}",
                detail.join(" "),
                log[tail..].join("\n  ")
            ));
        }
    }
    Ok(())
}

#[test]
fn audit4_lock_identity_matches_linux_flock_on_every_backing() {
    let seeds: u64 = std::env::var("AUDIT_SEEDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);
    let mut failures = Vec::new();
    for seed in 0..seeds {
        if let Err(text) = run(seed, 200) {
            failures.push(text);
        }
    }
    println!(
        "AUDIT-LOCK-PARITY seeds={seeds} failures={}",
        failures.len()
    );
    if let Some(first) = failures.first() {
        panic!("{} failure(s); first:\n{first}", failures.len());
    }
}

/// A power loss kills the lock holder: a new process takes every lock whose
/// name survived, even one the dead holder renamed; and the dead holder's
/// lock handle cannot release a lock taken after the crash.
#[test]
fn audit4_power_loss_releases_renamed_and_unlinked_locks() {
    let machine = CrashableBacking::new();
    let old = machine.process();
    old.create_dir_all("d").unwrap();
    let a = old.try_lock("a").unwrap();
    let c = old.try_lock("d/c").unwrap();
    old.sync_dir("").unwrap();
    old.sync_dir("d").unwrap();
    old.rename("a", "b").unwrap();
    old.sync_dir("").unwrap();
    old.remove("d/c").unwrap();
    // The unlink is volatile: the crash may keep or undo it.
    machine.crash_all_lost();
    let new = machine.process();
    let b = new
        .try_lock("b")
        .expect("renamed lock released by the power loss");
    let c2 = new.try_lock("d/c").expect("unlink undone, lock released");
    drop((a, c));
    assert_eq!(
        new.try_lock("b").err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock),
        "a dead holder's drop released a post-crash lock"
    );
    drop((b, c2));
    assert!(old.try_lock("b").is_err(), "a dead process took a lock");
}
