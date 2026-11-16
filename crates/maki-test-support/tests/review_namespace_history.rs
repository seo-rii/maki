//! Namespace crash outcomes must retain operation history and reachable parents.

use std::collections::BTreeSet;
use std::io::ErrorKind;

use maki_backing::Backing;
use maki_test_support::CrashableBacking;
use rand::{rngs::StdRng, SeedableRng};

fn write(backing: &CrashableBacking, path: &str, bytes: &[u8]) {
    let file = backing.open(path, true).unwrap();
    file.write_at(0, bytes).unwrap();
    file.sync_data().unwrap();
}

fn read(backing: &CrashableBacking, path: &str) -> Vec<u8> {
    let file = backing.open(path, false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

fn names(backing: &CrashableBacking) -> Vec<String> {
    backing.list("").unwrap()
}

#[test]
fn successive_renames_keep_one_name_and_every_intermediate_state() {
    for round_trip in [false, true] {
        let mut observed = BTreeSet::new();
        for seed in 0..256 {
            let backing = CrashableBacking::new();
            write(&backing, "a", b"original inode");
            backing.sync_dir("").unwrap();
            backing.rename("a", "b").unwrap();
            backing
                .rename("b", if round_trip { "a" } else { "c" })
                .unwrap();
            backing.crash(&mut StdRng::seed_from_u64(seed));
            let surviving = names(&backing);
            assert_eq!(surviving.len(), 1, "seed {seed}: {surviving:?}");
            assert_eq!(read(&backing, &surviving[0]), b"original inode");
            observed.insert(surviving[0].clone());
        }
        let expected = if round_trip {
            vec!["a", "b"]
        } else {
            vec!["a", "b", "c"]
        };
        assert_eq!(observed, expected.into_iter().map(str::to_owned).collect());
    }
}

#[test]
fn chained_replacements_never_mix_atomic_operations() {
    let allowed = BTreeSet::from([
        vec![
            ("a".into(), b"A".to_vec()),
            ("b".into(), b"B".to_vec()),
            ("c".into(), b"C".to_vec()),
        ],
        vec![("b".into(), b"A".to_vec()), ("c".into(), b"C".to_vec())],
        vec![("c".into(), b"A".to_vec())],
    ]);
    let mut observed = BTreeSet::new();
    for seed in 0..256 {
        let backing = CrashableBacking::new();
        for (name, bytes) in [("a", b"A"), ("b", b"B"), ("c", b"C")] {
            write(&backing, name, bytes);
        }
        backing.sync_dir("").unwrap();
        backing.rename("a", "b").unwrap();
        backing.rename("b", "c").unwrap();
        backing.crash(&mut StdRng::seed_from_u64(seed));
        let state: Vec<_> = names(&backing)
            .into_iter()
            .map(|name| {
                let bytes = read(&backing, &name);
                (name, bytes)
            })
            .collect();
        assert!(allowed.contains(&state), "seed {seed}: {state:?}");
        observed.insert(state);
    }
    assert_eq!(observed, allowed);
}

#[test]
fn pending_history_keeps_intermediate_inodes_after_handles_are_dropped() {
    let mut observed = BTreeSet::new();
    for seed in 0..512 {
        let backing = CrashableBacking::new();
        write(&backing, "f", b"OLD");
        backing.sync_dir("").unwrap();
        backing.remove("f").unwrap();
        write(&backing, "f", b"MIDDLE");
        backing.remove("f").unwrap();
        write(&backing, "f", b"NEW");
        backing.crash(&mut StdRng::seed_from_u64(seed));
        let state = backing.exists("f").unwrap().then(|| read(&backing, "f"));
        observed.insert(state);
    }
    assert_eq!(
        observed,
        BTreeSet::from([
            None,
            Some(b"OLD".to_vec()),
            Some(b"MIDDLE".to_vec()),
            Some(b"NEW".to_vec()),
        ])
    );
}

#[test]
fn independent_names_do_not_acquire_a_global_persistence_order() {
    let mut observed = BTreeSet::new();
    for seed in 0..128 {
        let backing = CrashableBacking::new();
        write(&backing, "a", b"A");
        write(&backing, "b", b"B");
        backing.crash(&mut StdRng::seed_from_u64(seed));
        observed.insert(names(&backing));
    }
    assert_eq!(
        observed,
        BTreeSet::from([
            vec![],
            vec!["a".into()],
            vec!["b".into()],
            vec!["a".into(), "b".into()],
        ])
    );
}

#[test]
fn syncing_one_directory_keeps_unrelated_history_volatile() {
    let backing = CrashableBacking::new();
    for dir in ["left", "right"] {
        backing.create_dir_all(dir).unwrap();
    }
    backing.sync_dir("").unwrap();
    write(&backing, "right/unsynced", b"RIGHT");
    write(&backing, "left/synced", b"LEFT");
    backing.sync_dir("left").unwrap();
    backing.crash_all_lost();
    assert_eq!(read(&backing, "left/synced"), b"LEFT");
    assert!(!backing.exists("right/unsynced").unwrap());
}

#[test]
fn child_sync_cannot_publish_ancestors_or_resurrect_orphan_files() {
    let backing = CrashableBacking::new();
    backing.create_dir_all("parent/child").unwrap();
    write(&backing, "parent/child/data", b"DATA");
    backing.sync_dir("parent/child").unwrap();
    backing.crash_all_lost();
    for path in ["parent", "parent/child", "parent/child/data"] {
        assert!(
            !backing.exists(path).unwrap(),
            "unreachable {path} survived"
        );
    }
    assert_eq!(
        backing
            .open("parent/child/data", false)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        backing.open("parent/child/new", true).err().unwrap().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        backing.list("parent/child").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        backing.sync_dir("parent/child").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    backing.create_dir_all("parent/child").unwrap();
    assert!(!backing.exists("parent/child/data").unwrap());
    assert!(backing.list("parent/child").unwrap().is_empty());
}

#[test]
fn published_nested_names_survive_and_random_crashes_never_leave_orphans() {
    for fully_published in [false, true] {
        for seed in 0..128 {
            let backing = CrashableBacking::new();
            backing.create_dir_all("parent/child").unwrap();
            write(&backing, "parent/child/data", b"DATA");
            backing.sync_dir("parent/child").unwrap();
            if fully_published {
                backing.sync_dir("parent").unwrap();
                backing.sync_dir("").unwrap();
            }
            backing.crash(&mut StdRng::seed_from_u64(seed));
            let parent = backing.exists("parent").unwrap();
            let child = backing.exists("parent/child").unwrap();
            let file = backing.exists("parent/child/data").unwrap();
            assert!(!child || parent);
            assert!(!file || child);
            if fully_published {
                assert!(parent && child && file);
            }
            if file {
                assert_eq!(read(&backing, "parent/child/data"), b"DATA");
            }
        }
    }
}

#[test]
fn pathname_operations_require_a_directory_parent() {
    let backing = CrashableBacking::new();
    write(&backing, "file", b"DATA");
    assert_eq!(
        backing.open("missing/child", true).err().unwrap().kind(),
        ErrorKind::NotFound
    );
    assert_eq!(
        backing.rename("file", "missing/child").unwrap_err().kind(),
        ErrorKind::NotFound
    );
    assert!(backing.create_dir_all("file/child").is_err());
    assert_eq!(read(&backing, "file"), b"DATA");
    backing.create_dir_all("dir").unwrap();
    assert!(backing.open("dir", true).is_err());
    assert!(backing.rename("file", "dir").is_err());
}

#[test]
fn syncing_either_rename_parent_commits_the_models_indivisible_operation() {
    // This model keeps cross-directory renames indivisible too. This is an
    // explicit model assumption, not a guarantee for every real filesystem.
    for synced in ["left", "right"] {
        let backing = CrashableBacking::new();
        backing.create_dir_all("left").unwrap();
        backing.create_dir_all("right").unwrap();
        backing.sync_dir("").unwrap();
        write(&backing, "left/a", b"DATA");
        backing.sync_dir("left").unwrap();
        backing.rename("left/a", "right/b").unwrap();
        backing.sync_dir(synced).unwrap();
        backing.crash_all_lost();
        assert!(!backing.exists("left/a").unwrap());
        assert_eq!(read(&backing, "right/b"), b"DATA");
    }
}

#[test]
fn torn_prefix_helper_preserves_the_selected_paths_history_and_ancestors() {
    let backing = CrashableBacking::new();
    backing.create_dir_all("parent/child").unwrap();
    write(&backing, "parent/child/a", b"OLD");
    backing.rename("parent/child/a", "parent/child/b").unwrap();
    backing.rename("parent/child/b", "parent/child/c").unwrap();
    let file = backing.open("parent/child/c", false).unwrap();
    file.write_at(0, b"NEW").unwrap();
    drop(file);
    backing.crash_keep_torn_prefix("parent/child/c", 1);
    assert_eq!(read(&backing, "parent/child/c"), b"NLD");
    assert!(backing.exists("parent").unwrap());
    assert!(backing.exists("parent/child").unwrap());
    assert_eq!(backing.list("parent/child").unwrap(), vec!["c"]);
}

#[test]
fn compacted_history_stays_ordered_across_later_renames() {
    let mut observed = BTreeSet::new();
    for seed in 0..128 {
        let backing = CrashableBacking::new();
        backing.create_dir_all("left").unwrap();
        backing.create_dir_all("right").unwrap();
        backing.sync_dir("").unwrap();
        write(&backing, "left/a", b"DATA");
        backing.sync_dir("left").unwrap();
        backing.rename("left/a", "right/b").unwrap();
        backing.rename("right/b", "right/c").unwrap();
        backing.sync_dir("left").unwrap();
        // The first rename is now durable; the second still depends on it.
        backing.rename("right/c", "right/b").unwrap();
        backing.crash(&mut StdRng::seed_from_u64(seed));
        assert!(backing.list("left").unwrap().is_empty());
        let surviving = backing.list("right").unwrap();
        assert_eq!(surviving.len(), 1);
        assert_eq!(read(&backing, &format!("right/{}", surviving[0])), b"DATA");
        observed.insert(surviving);
    }
    assert_eq!(
        observed,
        BTreeSet::from([vec!["b".into()], vec!["c".into()]])
    );
}

#[test]
fn restored_file_blocks_a_volatile_directory_with_the_same_name() {
    let backing = CrashableBacking::new();
    write(&backing, "parent", b"OLD FILE");
    backing.sync_dir("").unwrap();
    backing.remove("parent").unwrap();
    backing.create_dir_all("parent/child").unwrap();
    write(&backing, "parent/child/data", b"DATA");
    backing.sync_dir("parent/child").unwrap();
    backing.sync_dir("parent").unwrap();
    backing.crash_all_lost();
    assert_eq!(read(&backing, "parent"), b"OLD FILE");
    assert_eq!(
        backing
            .open("parent/child/data", false)
            .err()
            .unwrap()
            .kind(),
        ErrorKind::NotADirectory
    );
}

#[test]
fn torn_prefix_can_preserve_a_directory_replacing_a_durable_file() {
    let backing = CrashableBacking::new();
    write(&backing, "parent", b"OLD FILE");
    backing.sync_dir("").unwrap();
    backing.remove("parent").unwrap();
    backing.create_dir_all("parent/child").unwrap();
    write(&backing, "parent/child/data", b"OLD");
    let file = backing.open("parent/child/data", false).unwrap();
    file.write_at(0, b"NEW").unwrap();
    drop(file);
    backing.crash_keep_torn_prefix("parent/child/data", 1);
    assert_eq!(read(&backing, "parent/child/data"), b"NLD");
}
