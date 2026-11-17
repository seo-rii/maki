//! A power loss kills every process. No file or lock handle opened before a
//! `crash*()` may work afterwards or change the recovered state, and neither
//! may a process view (`CrashableBacking::process`) started before it; a test
//! that crashes while something still holds a handle or a view would
//! otherwise observe a state no power loss can produce. A process restart
//! (`drop` + reopen, or a new view) is not a crash and invalidates nothing.

use std::io::{self, ErrorKind};
use std::sync::Arc;

use maki_backing::{Backing, BackingFile};
use maki_test_support::crash_backing::CrashableBacking;
use rand::rngs::StdRng;
use rand::SeedableRng;

fn read_all(backing: &CrashableBacking, path: &str) -> Vec<u8> {
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

/// The root's names and the bytes of every file in it.
fn root_state(backing: &CrashableBacking) -> Vec<(String, Option<Vec<u8>>)> {
    backing
        .list("")
        .unwrap()
        .into_iter()
        .map(|name| match backing.open(&name, false) {
            Ok(_) => {
                let bytes = read_all(backing, &name);
                (name, Some(bytes))
            }
            Err(error) if error.kind() == ErrorKind::IsADirectory => (name, None),
            Err(error) => panic!("{name}: {error}"),
        })
        .collect()
}

fn assert_dead(result: io::Result<impl std::fmt::Debug>, op: &str, crash: &str) {
    let error = result.expect_err(&format!("{op} through a pre-crash handle after {crash}"));
    assert_eq!(
        error.kind(),
        ErrorKind::Other,
        "{op} after {crash}: {error}"
    );
}

type Crash = fn(&CrashableBacking);

const CRASHES: [(&str, Crash); 3] = [
    ("crash", |backing| {
        backing.crash(&mut StdRng::seed_from_u64(7))
    }),
    ("crash_all_lost", |backing| backing.crash_all_lost()),
    ("crash_keep_torn_prefix", |backing| {
        backing.crash_keep_torn_prefix("f", 2)
    }),
];

#[test]
fn a_handle_opened_before_a_power_loss_is_dead_afterwards() {
    for (crash, power_loss) in CRASHES {
        let backing = CrashableBacking::new();
        let file = backing.open("f", true).unwrap();
        file.write_at(0, b"old").unwrap();
        file.sync_data().unwrap();
        backing.sync_dir("").unwrap();
        file.write_at(3, b" pending").unwrap();

        power_loss(&backing);
        let recovered = read_all(&backing, "f");

        let mut buf = [0; 3];
        assert_dead(file.read_at(0, &mut buf), "read_at", crash);
        assert_dead(file.write_at(0, b"new"), "write_at", crash);
        assert_dead(file.punch_hole(0, 1), "punch_hole", crash);
        assert_dead(file.set_len(1), "set_len", crash);
        assert_dead(file.len(), "len", crash);
        assert_dead(file.sync_data(), "sync_data", crash);
        drop(file);
        backing.crash_all_lost();
        assert_eq!(
            read_all(&backing, "f"),
            recovered,
            "{crash}: a pre-crash handle changed the recovered state"
        );

        // The post-crash world works through new handles.
        let file = backing.open("f", false).unwrap();
        file.write_at(0, b"new").unwrap();
        file.sync_data().unwrap();
        backing.crash_all_lost();
        assert_eq!(&read_all(&backing, "f")[..3], b"new", "{crash}");
    }
}

/// Dropping a stale handle must not release state that a post-crash handle
/// holds: an unlinked file stays readable while a new handle keeps it open.
#[test]
fn dropping_a_pre_crash_handle_leaves_post_crash_handles_alone() {
    for (crash, power_loss) in CRASHES {
        let backing = CrashableBacking::new();
        let stale = backing.open("f", true).unwrap();
        stale.write_at(0, b"data").unwrap();
        stale.sync_data().unwrap();
        backing.sync_dir("").unwrap();

        power_loss(&backing);
        let live: Arc<dyn BackingFile> = backing.open("f", false).unwrap();
        backing.remove("f").unwrap();
        backing.sync_dir("").unwrap();
        drop(stale);
        let mut buf = [0; 4];
        live.read_at(0, &mut buf).unwrap_or_else(|error| {
            panic!("{crash}: an unlinked file open after the crash vanished: {error}")
        });
        assert_eq!(&buf, b"data", "{crash}");
    }
}

/// A power loss releases every lock its processes held; the dead holder's
/// handle cannot release a lock taken after the crash.
#[test]
fn a_power_loss_releases_the_volume_lock_of_the_dead_process() {
    for (crash, power_loss) in CRASHES {
        let backing = CrashableBacking::new();
        drop(backing.open("f", true).unwrap());
        backing.sync_dir("").unwrap();
        let stale = backing.try_lock("volume.lock").unwrap();

        power_loss(&backing);
        let live = backing
            .try_lock("volume.lock")
            .unwrap_or_else(|error| panic!("{crash}: the dead process still holds it: {error}"));
        drop(stale);
        assert_eq!(
            backing.try_lock("volume.lock").err().map(|e| e.kind()),
            Some(ErrorKind::WouldBlock),
            "{crash}: dropping the dead holder's handle released the new lock"
        );
        drop(live);
        drop(backing.try_lock("volume.lock").unwrap());
    }
}

/// A restart is not a power loss: closing and reopening keeps the page
/// cache, and handles of the same run keep working.
#[test]
fn a_restart_invalidates_no_handle() {
    let backing = CrashableBacking::new();
    let first = backing.open("f", true).unwrap();
    first.write_at(0, b"cached").unwrap();
    let second = backing.open("f", false).unwrap();
    drop(first);
    let mut buf = [0; 6];
    second.read_at(0, &mut buf).unwrap();
    assert_eq!(&buf, b"cached");
    second.sync_data().unwrap();

    // Neither does starting another process.
    let earlier = backing.process();
    let later = backing.process();
    drop(later.open("g", true).unwrap());
    assert!(earlier.exists("g").unwrap());
    earlier.sync_dir("").unwrap();
}

/// Every namespace operation of a process started before a power loss
/// fails afterwards and changes nothing: the process is dead, even if the
/// test still holds its view (an undropped volume or engine, a worker in
/// the middle of a pass). The backing the test created, and processes
/// started after the crash, keep working.
#[test]
fn a_process_started_before_a_power_loss_is_dead_afterwards() {
    for (crash, power_loss) in CRASHES {
        let backing = CrashableBacking::new();
        let dead = backing.process();
        dead.create_dir_all("d").unwrap();
        let file = dead.open("f", true).unwrap();
        file.write_at(0, b"old").unwrap();
        file.sync_data().unwrap();
        dead.sync_dir("").unwrap();
        drop(file);
        let file = dead.open("f", false).unwrap();
        file.write_at(3, b" pending").unwrap();
        drop(file);
        let lock = dead.try_lock("volume.lock").unwrap();
        let same_process = dead.clone();

        power_loss(&backing);
        let recovered = root_state(&backing);

        for view in [&dead, &same_process] {
            assert_dead(view.open("f", false).map(drop), "open", crash);
            assert_dead(view.open("new", true).map(drop), "open (create)", crash);
            assert_dead(view.exists("f"), "exists", crash);
            assert_dead(view.remove("f"), "remove", crash);
            assert_dead(view.rename("f", "g"), "rename", crash);
            assert_dead(view.create_dir_all("e"), "create_dir_all", crash);
            assert_dead(view.list(""), "list", crash);
            assert_dead(view.sync_dir(""), "sync_dir", crash);
            assert_dead(view.sync_dir("d"), "sync_dir (subdirectory)", crash);
            assert_dead(view.try_lock("other.lock").map(drop), "try_lock", crash);
            assert_dead(view.free_bytes(), "free_bytes", crash);
            assert_dead(view.check_freshness(), "check_freshness", crash);
        }
        drop((dead, same_process, lock));
        backing.crash_all_lost();
        assert_eq!(
            root_state(&backing),
            recovered,
            "{crash}: a dead process changed the recovered state"
        );

        // A process started after the crash works, and so does the backing.
        let live = backing.process();
        let file = live.open("g", true).unwrap();
        file.write_at(0, b"new").unwrap();
        file.sync_data().unwrap();
        live.sync_dir("").unwrap();
        drop(live.try_lock("volume.lock").unwrap());
        drop(file);
        backing.crash_all_lost();
        assert_eq!(read_all(&backing, "g"), b"new", "{crash}");
        assert!(backing.exists("f").unwrap(), "{crash}");
    }
}
