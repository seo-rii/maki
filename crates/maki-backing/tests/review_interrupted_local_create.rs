//! A local rollback `volume create` writes the backing's format marker,
//! reserves the arena and the manifest slots, writes the initial manifest,
//! and publishes the witness anchor last. Until the anchor is published
//! nothing can open the volume and nothing was ever acknowledged, so a
//! creation that is killed, loses power or fails on its way (a full disk,
//! a quota, an I/O error) has lost nothing. It must also leave a pair of
//! directories that `volume create` completes when it is run again. A
//! creation that created a file and was cut before filling it (the marker,
//! the witness anchor) or that stopped after the marker was neither
//! continued by `create`, which wants both directories empty, nor opened.
//!
//! What `create` may complete is only what a creation leaves: never a
//! backing that holds a volume's committed manifest, whatever the witness
//! directory holds (an unmounted witness is an empty directory), and never
//! a witness that holds an anchor.
//!
//! The interrupted commands run in child processes with a seccomp filter
//! that kills them at, or fails, one system call.
#![cfg(target_os = "linux")]

#[path = "support/other_filesystem.rs"]
mod other_filesystem;
#[path = "support/seccomp.rs"]
mod seccomp;

use std::path::Path;
use std::process::Command;

use maki_backing::{Backing, RollbackBacking};

const CAPACITY: u64 = 16 * 4096;

/// The backing root and the witness directory, on two filesystems, or
/// `None` where there is no second one (the test then says it is skipped).
fn directories() -> Option<(tempfile::TempDir, tempfile::TempDir)> {
    let root = tempfile::tempdir().unwrap();
    let witness = other_filesystem::tempdir(root.path())?;
    Some((root, witness))
}

fn entries(directory: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(directory)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn commit(backing: &RollbackBacking, data: &[u8]) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, data).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

fn read(backing: &RollbackBacking) -> Vec<u8> {
    let file = backing.open("payload", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

const STEP: &str = "MAKI_INTERRUPTED_LOCAL_CREATE_STEP";
const ROOT: &str = "MAKI_INTERRUPTED_LOCAL_CREATE_ROOT";
const WITNESS: &str = "MAKI_INTERRUPTED_LOCAL_CREATE_WITNESS";
/// Exit status of a creation that returned an error.
const FAILED: i32 = 3;
/// Exit status of a step that could not arrange its interruption.
const UNAVAILABLE: i32 = 77;
/// The length of a witness anchor record.
const ANCHOR_LENGTH: u32 = 104;

/// The interrupted creation, in the child process. Never returns.
fn step(step: &str, root: &Path, witness: &Path) -> ! {
    let arranged = match step {
        // The format marker is the first file a creation writes.
        "killed at the first write" => seccomp::on(libc::SYS_pwrite64, None, seccomp::KILLS),
        "out of space for the arena" => {
            seccomp::on(libc::SYS_fallocate, None, seccomp::fails_with(libc::ENOSPC))
        }
        "killed writing the anchor" => {
            seccomp::on(libc::SYS_pwrite64, Some(ANCHOR_LENGTH), seccomp::KILLS)
        }
        "out of space for the anchor" => seccomp::on(
            libc::SYS_pwrite64,
            Some(ANCHOR_LENGTH),
            seccomp::fails_with(libc::ENOSPC),
        ),
        other => panic!("unknown step {other}"),
    };
    if !arranged {
        std::process::exit(UNAVAILABLE);
    }
    let outcome = RollbackBacking::create(root, witness, CAPACITY).map(drop);
    eprintln!("create: {outcome:?}");
    std::process::exit(if outcome.is_ok() { 0 } else { FAILED });
}

/// The child half of a test that interrupts a creation.
fn child() {
    if let (Some(name), Some(root), Some(witness)) = (
        std::env::var_os(STEP),
        std::env::var_os(ROOT),
        std::env::var_os(WITNESS),
    ) {
        step(
            name.to_str().unwrap(),
            Path::new(&root),
            Path::new(&witness),
        );
    }
}

/// Run `step` in a child process that re-enters `test`. `None`, with the
/// reason printed, where the interruption cannot be arranged.
fn interrupted(
    test: &str,
    step: &str,
    root: &Path,
    witness: &Path,
) -> Option<std::process::Output> {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", test, "--nocapture", "--test-threads=1"])
        .env(STEP, step)
        .env(ROOT, root)
        .env(WITNESS, witness)
        .output()
        .unwrap();
    if output.status.code() == Some(UNAVAILABLE) {
        eprintln!("{test}: skipped: cannot arrange `{step}` in a child process");
        return None;
    }
    Some(output)
}

/// Run `volume create` again after the interrupted one and use the volume:
/// it must complete, and what it creates is an ordinary volume.
fn create_again(root: &Path, witness: &Path, interrupted: &std::process::Output) {
    let left = (entries(root), entries(witness));
    let created = RollbackBacking::create(root, witness, CAPACITY).unwrap_or_else(|error| {
        let opened = RollbackBacking::open(root, witness).err();
        panic!(
            "an interrupted creation is stranded with {left:?}: create: {error}; open: {opened:?}; \
             the interrupted run: {interrupted:?}"
        )
    });
    commit(&created, b"kept");
    drop(created);
    // Nothing is left under a temporary name.
    assert!(!root.join("rollback.format.next").exists());
    assert!(!witness.join("anchor.next").exists());
    let reopened = RollbackBacking::open(root, witness).unwrap();
    assert_eq!(read(&reopened), b"kept");
}

/// Earlier releases created the marker and then wrote it. A backing in
/// which one left it empty or torn, beside nothing but the lock, is
/// completed like an empty one; so is a marker staged by this release.
#[test]
fn create_completes_a_backing_whose_marker_was_never_written() {
    assert!(RollbackBacking::owns_host_entry(
        "rollback.format.next",
        false
    ));
    const MARKER: &[u8] = b"MAKI-WITNESS-COW-V1\n";
    let mut torn = MARKER.to_vec();
    torn[7..].fill(0);
    for (name, bytes) in [
        ("rollback.format", &[][..]),
        ("rollback.format", &torn[..]),
        ("rollback.format.next", &MARKER[..4]),
    ] {
        let Some((root, witness)) = directories() else {
            return;
        };
        std::fs::write(root.path().join("rollback.lock"), b"").unwrap();
        std::fs::write(root.path().join(name), bytes).unwrap();
        let unchanged = std::process::Command::new("true").output().unwrap();
        create_again(root.path(), witness.path(), &unchanged);
        assert_eq!(
            std::fs::read(root.path().join("rollback.format")).unwrap(),
            MARKER
        );
    }
}

#[test]
fn create_killed_at_its_first_write_can_be_run_again() {
    use std::os::unix::process::ExitStatusExt;
    child();
    let Some((root, witness)) = directories() else {
        return;
    };
    let Some(killed) = interrupted(
        "create_killed_at_its_first_write_can_be_run_again",
        "killed at the first write",
        root.path(),
        witness.path(),
    ) else {
        return;
    };
    assert_eq!(killed.status.signal(), Some(libc::SIGSYS), "{killed:?}");
    assert!(entries(witness.path()).is_empty());
    create_again(root.path(), witness.path(), &killed);
}

#[test]
fn create_that_ran_out_of_space_for_its_arena_can_be_run_again() {
    child();
    let Some((root, witness)) = directories() else {
        return;
    };
    let Some(failed) = interrupted(
        "create_that_ran_out_of_space_for_its_arena_can_be_run_again",
        "out of space for the arena",
        root.path(),
        witness.path(),
    ) else {
        return;
    };
    assert_eq!(failed.status.code(), Some(FAILED), "{failed:?}");
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("No space left on device"),
        "{failed:?}"
    );
    assert!(root.path().join("rollback.arena").exists());
    create_again(root.path(), witness.path(), &failed);
}

#[test]
fn create_killed_while_writing_its_witness_anchor_can_be_run_again() {
    use std::os::unix::process::ExitStatusExt;
    child();
    let Some((root, witness)) = directories() else {
        return;
    };
    let Some(killed) = interrupted(
        "create_killed_while_writing_its_witness_anchor_can_be_run_again",
        "killed writing the anchor",
        root.path(),
        witness.path(),
    ) else {
        return;
    };
    assert_eq!(killed.status.signal(), Some(libc::SIGSYS), "{killed:?}");
    assert!(root.path().join("rollback.manifest.0").exists());
    create_again(root.path(), witness.path(), &killed);
}

#[test]
fn create_that_ran_out_of_space_for_its_witness_anchor_can_be_run_again() {
    child();
    let Some((root, witness)) = directories() else {
        return;
    };
    let Some(failed) = interrupted(
        "create_that_ran_out_of_space_for_its_witness_anchor_can_be_run_again",
        "out of space for the anchor",
        root.path(),
        witness.path(),
    ) else {
        return;
    };
    assert_eq!(failed.status.code(), Some(FAILED), "{failed:?}");
    assert!(
        String::from_utf8_lossy(&failed.stderr).contains("No space left on device"),
        "{failed:?}"
    );
    create_again(root.path(), witness.path(), &failed);
}

/// A witness directory that is not mounted is an empty directory. The
/// backing of a volume that committed anything is never created over,
/// whatever the witness directory holds.
#[test]
fn control_create_refuses_a_used_backing_beside_an_empty_witness_directory() {
    let Some((root, witness)) = directories() else {
        return;
    };
    let backing = RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap();
    commit(&backing, b"committed");
    drop(backing);
    let before = std::fs::read(root.path().join("rollback.manifest.1")).unwrap();
    let Some(unmounted) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    for witness in [unmounted.path(), witness.path()] {
        assert!(RollbackBacking::create(root.path(), witness, CAPACITY).is_err());
    }
    assert!(entries(unmounted.path()).is_empty());
    assert_eq!(
        std::fs::read(root.path().join("rollback.manifest.1")).unwrap(),
        before
    );
    let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
    assert_eq!(read(&reopened), b"committed");
}

/// Damage that reads back as bytes, a length field or one byte of a
/// manifest, does not make a committed volume's manifest slots look unused.
/// Beside a witness directory without an anchor (one that lost it, or is
/// not mounted), `create` refuses the backing and changes nothing: a slot
/// that holds anything but zeros, or, in slot 0, the initial generation-0
/// manifest, belongs to a volume, whatever state it is in.
#[test]
fn create_refuses_a_committed_backing_whose_manifest_slots_are_damaged() {
    use std::os::unix::fs::FileExt;
    type Damage = fn(&Path);
    let header: Damage = |slot| {
        let file = std::fs::OpenOptions::new().write(true).open(slot).unwrap();
        file.write_all_at(&[0xff; 8], 0).unwrap();
    };
    let body: Damage = |slot| {
        let file = std::fs::OpenOptions::new().write(true).open(slot).unwrap();
        file.write_all_at(b"#", 8).unwrap();
    };
    // Slot 1 as `open` recreates a missing inactive slot: zeros.
    let zeroed: Damage = |slot| {
        let file = std::fs::OpenOptions::new().write(true).open(slot).unwrap();
        let len = file.metadata().unwrap().len();
        file.set_len(0).unwrap();
        file.set_len(len).unwrap();
    };
    let mut created_over = Vec::new();
    for (what, slot0, slot1) in [
        ("both lengths", header, header),
        ("a byte of both", body, body),
        ("the length of slot 0, slot 1 zeroed", header, zeroed),
        ("a byte of slot 0, slot 1 zeroed", body, zeroed),
    ] {
        let Some((root, witness)) = directories() else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap();
        commit(&backing, b"committed");
        let file = backing.open("second", true).unwrap();
        file.write_at(0, b"committed too").unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        drop((file, backing));
        slot0(&root.path().join("rollback.manifest.0"));
        slot1(&root.path().join("rollback.manifest.1"));
        std::fs::remove_file(witness.path().join("anchor")).unwrap();
        let slots = |root: &Path| {
            ["rollback.manifest.0", "rollback.manifest.1"]
                .map(|slot| std::fs::read(root.join(slot)).unwrap())
        };
        let state = || {
            (
                entries(root.path()),
                entries(witness.path()),
                slots(root.path()),
            )
        };
        let before = state();
        if RollbackBacking::create(root.path(), witness.path(), CAPACITY).is_ok()
            || state() != before
        {
            created_over.push(what);
        }
    }
    assert!(
        created_over.is_empty(),
        "create completed over, or changed, a backing that committed data: {created_over:?}"
    );
}

/// A creation never writes the second manifest slot; a volume's first
/// commit does. Beside the initial manifest in slot 0, which is what a
/// volume that committed once still holds there, a second slot holding
/// anything but zeros is that commit in whatever state damage left it.
#[test]
fn create_refuses_a_second_manifest_slot_that_holds_anything() {
    use std::os::unix::fs::FileExt;
    for damage in [&[0xff; 8][..], b"#", &[1]] {
        let Some((root, witness)) = directories() else {
            return;
        };
        drop(RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap());
        let slot = root.path().join("rollback.manifest.1");
        std::fs::OpenOptions::new()
            .write(true)
            .open(&slot)
            .unwrap()
            .write_all_at(damage, 4096)
            .unwrap();
        std::fs::remove_file(witness.path().join("anchor")).unwrap();
        let before = std::fs::read(&slot).unwrap();
        assert!(
            RollbackBacking::create(root.path(), witness.path(), CAPACITY).is_err(),
            "{damage:?}"
        );
        assert_eq!(std::fs::read(&slot).unwrap(), before);
        assert!(entries(witness.path()).iter().all(|name| name != "anchor"));
    }
}

/// Not even the initial manifest is accepted in the second slot: only slot
/// 0 ever holds it, and a copy of it in slot 1 is no state a creation or a
/// commit leaves.
#[test]
fn create_refuses_the_initial_manifest_in_the_second_slot() {
    let Some((root, witness)) = directories() else {
        return;
    };
    drop(RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap());
    let initial = std::fs::read(root.path().join("rollback.manifest.0")).unwrap();
    std::fs::write(root.path().join("rollback.manifest.1"), &initial).unwrap();
    std::fs::remove_file(witness.path().join("anchor")).unwrap();
    let before = (entries(root.path()), entries(witness.path()));
    assert!(RollbackBacking::create(root.path(), witness.path(), CAPACITY).is_err());
    assert_eq!((entries(root.path()), entries(witness.path())), before);
    assert_eq!(
        std::fs::read(root.path().join("rollback.manifest.1")).unwrap(),
        initial
    );
}

/// An anchor that is empty is what an earlier release's creation left when
/// it was cut after installing it, and also what a witness whose anchor
/// was truncated looks like. `create` never writes over an anchor, and
/// `open` refuses it and says what to do. The way out it gives, removing
/// the empty anchor, completes a volume that was never written, and still
/// refuses one that committed data.
#[test]
fn control_create_and_open_refuse_a_witness_that_holds_an_empty_anchor() {
    for committed in [false, true] {
        let Some((root, witness)) = directories() else {
            return;
        };
        let backing = RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap();
        if committed {
            commit(&backing, b"committed");
        }
        drop(backing);
        std::fs::OpenOptions::new()
            .write(true)
            .truncate(true)
            .open(witness.path().join("anchor"))
            .unwrap();
        let before = (entries(root.path()), entries(witness.path()));
        assert!(RollbackBacking::create(root.path(), witness.path(), CAPACITY).is_err());
        assert_eq!((entries(root.path()), entries(witness.path())), before);
        assert_eq!(
            std::fs::metadata(witness.path().join("anchor"))
                .unwrap()
                .len(),
            0
        );
        let error = RollbackBacking::open(root.path(), witness.path())
            .err()
            .unwrap()
            .to_string();
        assert!(
            error.contains("the witness anchor is empty")
                && error.contains("did not complete")
                && error.contains("lost its state")
                && error.contains("never attached"),
            "{error}"
        );
        std::fs::remove_file(witness.path().join("anchor")).unwrap();
        let created = RollbackBacking::create(root.path(), witness.path(), CAPACITY);
        assert_eq!(created.is_ok(), !committed, "committed: {committed}");
    }
}

/// Only a backing that holds what a creation leaves is completed: an entry
/// no creation writes is refused and left as it is.
#[test]
fn control_create_refuses_a_backing_that_holds_anything_else() {
    let Some((root, witness)) = directories() else {
        return;
    };
    std::fs::write(root.path().join("rollback.lock"), b"").unwrap();
    std::fs::write(root.path().join("rollback.format"), b"").unwrap();
    std::fs::write(root.path().join("notes"), b"operator").unwrap();
    let before = entries(root.path());
    assert!(RollbackBacking::create(root.path(), witness.path(), CAPACITY).is_err());
    assert_eq!(entries(root.path()), before);
    assert!(entries(witness.path()).is_empty());
}

/// Until `create` is run again, the daemon, `maki check` and `maki volume
/// inspect` open the pair an interrupted creation left. They must say what
/// it is and what continues it, not only that a file is missing, and keep
/// the error kind of a missing file.
#[test]
fn open_names_an_interrupted_creation_and_what_continues_it() {
    // Stopped before the marker was published.
    let Some((root, witness)) = directories() else {
        return;
    };
    std::fs::write(root.path().join("rollback.lock"), b"").unwrap();
    std::fs::write(root.path().join("rollback.format.next"), b"MAKI").unwrap();
    let error = RollbackBacking::open(root.path(), witness.path())
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
    let text = error.to_string();
    assert!(
        text.contains("rollback.format") && text.contains("volume create"),
        "{text}"
    );

    // Stopped before the anchor was published: the backing is complete.
    // A witness mount that is not mounted looks the same, so both causes
    // are named.
    let Some((root, witness)) = directories() else {
        return;
    };
    drop(RollbackBacking::create(root.path(), witness.path(), CAPACITY).unwrap());
    std::fs::remove_file(witness.path().join("anchor")).unwrap();
    let error = RollbackBacking::open(root.path(), witness.path())
        .err()
        .unwrap();
    assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}");
    let text = error.to_string();
    assert!(
        text.contains("no anchor") && text.contains("volume create") && text.contains("mounted"),
        "{text}"
    );
    let unchanged = std::process::Command::new("true").output().unwrap();
    create_again(root.path(), witness.path(), &unchanged);
}
