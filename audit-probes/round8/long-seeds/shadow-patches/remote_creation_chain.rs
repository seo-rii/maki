
// ---------------------------------------------------------------------------
// AUDIT ROUND 8 (long-seeds), appended in the shadow copy only: a remote
// creation interrupted one to four times in a row (random operation, process
// death or single failed operation, optional power loss), each time followed
// by the documented next command for the state it left (create again while
// the marker is not published, enrollment recovery once it is), itself
// interrupted; then the committed `complete_binding`.
#[test]
fn audit8_a_remote_creation_interrupted_repeatedly_can_be_continued() {
    use rand::Rng;
    let ops = operations_of(attempt_binding);
    let resume = |machine: &CrashableBacking| -> bool {
        let process = machine.process();
        let Ok(_enrollment) = process.try_lock(super::super::ENROLL_LOCK) else {
            return false;
        };
        Enrollment::verify_if_present(process.as_ref(), IDENTITY, CAPACITY).is_ok()
            && Enrollment::load_or_create(process.as_ref(), IDENTITY, CAPACITY).is_ok()
    };
    let done = std::cell::Cell::new(0u64);
    let commands = std::cell::Cell::new(0u64);
    // Seeds are isolated so that one known failure class does not hide
    // another: F1 = a staged binding beside an unpublished marker.
    let mut known = Vec::new();
    let mut other = Vec::new();
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    for seed in crate::a8::seeds(0..=300) {
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut rng = StdRng::seed_from_u64(seed ^ 0xA8C4_0002);
            let machine = machine();
            let mut context = format!("seed {seed}");
            for _ in 0..rng.random_range(1..=4) {
                let cut = rng.random_range(0..=ops + 2);
                let single = rng.random_bool(0.3);
                let was_published = published(&machine);
                one_command_continues(&machine, &context);
                inject(&machine, move |index| {
                    if single {
                        index == cut
                    } else {
                        index >= cut
                    }
                });
                let ok = if was_published {
                    resume(&machine)
                } else {
                    attempt_binding(&machine).is_ok()
                };
                machine.set_fault_hook(None);
                let loss = rng.random_range(0..4u64);
                match loss {
                    0 => {}
                    1 => machine.crash_all_lost(),
                    _ => machine.crash(&mut StdRng::seed_from_u64(rng.random_range(1..u64::MAX))),
                }
                commands.set(commands.get() + 1);
                context += &format!(
                    "; {} cut {cut}{} -> ok={ok}, loss {loss}",
                    if was_published { "resume" } else { "create" },
                    if single { " (single failure)" } else { " (death)" },
                );
            }
            complete_binding(&machine, &context);
            done.set(done.get() + 1);
        }));
        if let Err(payload) = outcome {
            let text = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default();
            if text.contains("marker published: false")
                && text.contains("remote enrollment requires an empty backing")
                && text.contains("remote.enrollment.next")
            {
                known.push(seed);
            } else {
                other.push(format!("seed {seed}: {text}"));
            }
        }
    }
    std::panic::set_hook(previous);
    println!(
        "AUDIT8 remote creation chains: seeds completed {}, interrupted commands {}, F1 (staged \
         binding beside an unpublished marker) seeds {} {:?}, other failures {}",
        done.get(),
        commands.get(),
        known.len(),
        &known[..known.len().min(12)],
        other.len()
    );
    assert!(
        other.is_empty(),
        "{} failure(s) outside the known class; first 3:\n{}",
        other.len(),
        other.iter().take(3).cloned().collect::<Vec<_>>().join("\n")
    );
    if std::env::var_os("AUDIT8_STRICT").is_some() {
        assert!(known.is_empty(), "F1 seeds: {known:?}");
    }
}

/// AUDIT ROUND 8, minimised from the chain sweep above (seed 160709).
///
/// 1. `maki volume create`: the directory sync that publishes the format
///    marker fails once (EIO). The command fails; `rollback.format` is
///    readable but its name is not durable.
/// 2. The documented next command for a root whose marker is readable is
///    enrollment recovery (`recover_enrollment_remote`, remote.rs:590-598):
///    it rewrites and syncs the marker's *data* and stages the binding as
///    `remote.enrollment.next`. Power is lost before the binding's rename.
/// 3. The crash keeps the staged binding's directory entry and loses the
///    marker's rename (they are different names; nothing synced the
///    directory in between).
///
/// The root now holds `rollback.format.next` and `remote.enrollment.next`:
/// `volume create` refuses it ("remote enrollment requires an empty
/// backing") and enrollment recovery has no marker to open. Neither
/// documented command continues, although nothing was published or claimed.
#[test]
fn audit8_a_binding_staged_over_a_volatile_marker_leaves_a_root_no_command_continues() {
    use crate::rollback::review_restore::crash_backing::FaultOp;
    use std::sync::atomic::AtomicBool;
    let machine = machine();

    // 1. The marker's directory sync fails; the creation reports the failure.
    let failed = Arc::new(AtomicBool::new(false));
    let seen = failed.clone();
    machine.set_fault_hook(Some(Arc::new(move |op| {
        (matches!(op, FaultOp::SyncDir { .. }) && !seen.swap(true, Ordering::SeqCst))
            .then(|| io::Error::from_raw_os_error(libc::EIO))
    })));
    assert!(attempt_binding(&machine).is_err());
    machine.set_fault_hook(None);
    assert!(failed.load(Ordering::SeqCst));
    assert!(published(&machine), "the marker is readable after the failed directory sync");
    // So far the documented rule holds: create refuses, recovery continues.
    one_command_continues(&machine, "after the failed directory sync");

    // 2. Enrollment recovery, statement for statement (remote.rs:590-598),
    //    until the process dies at the binding's rename.
    {
        let process = machine.process();
        let _enrollment = process.try_lock(super::super::ENROLL_LOCK).unwrap();
        assert!(!Enrollment::verify_if_present(process.as_ref(), IDENTITY, CAPACITY).unwrap());
        let marker = process.open(MARKER, false).unwrap();
        marker.write_at(0, REMOTE_MAGIC).unwrap();
        marker.set_len(REMOTE_MAGIC.len() as u64).unwrap();
        marker.sync_data().unwrap();
        let dead = Arc::new(AtomicBool::new(false));
        let died = dead.clone();
        machine.set_fault_hook(Some(Arc::new(move |op| {
            if matches!(op, FaultOp::Rename { .. }) {
                died.store(true, Ordering::SeqCst);
            }
            died.load(Ordering::SeqCst)
                .then(|| io::Error::from_raw_os_error(libc::EIO))
        })));
        assert!(Enrollment::load_or_create(process.as_ref(), IDENTITY, CAPACITY).is_err());
        assert!(dead.load(Ordering::SeqCst));
        machine.set_fault_hook(None);
    }

    // 3. Power loss: the staged binding's name is on disk, the marker's
    //    rename is not (every other volatile operation is lost).
    machine.crash_keep_torn_prefix(super::super::enrollment::FILE_NEXT, usize::MAX);

    let root = machine.process().list("").unwrap();
    let create = require_empty_remote_root(machine.process().as_ref());
    println!(
        "AUDIT8 root after the power loss: {root:?}; marker published: {}; create: {create:?}",
        published(&machine)
    );
    assert!(!published(&machine), "enrollment recovery has a marker to open");
    assert!(
        create.is_ok(),
        "neither command continues the root {root:?}: no marker for enrollment recovery, and \
         create answers {create:?}"
    );
}
