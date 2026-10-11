#![cfg(target_os = "linux")]

use std::io;
use std::sync::Mutex;

use maki_backing::remote_gc::OperationGuard;
use maki_backing::remote_witness::{namespace, Action, Descriptor, Phase, Record, Request, Rpc};
use maki_backing::witness::Anchor;
use maki_backing::{Backing, FileBacking};
use serde::Serialize;
use sha2::{Digest, Sha256};

#[derive(Serialize)]
struct EmptyManifest {
    format: u32,
    identity: [u8; 16],
    generation: u64,
    capacity: u64,
    next_id: u64,
    entries: std::collections::BTreeMap<String, String>,
    files: std::collections::BTreeMap<u64, String>,
}

fn manifest_bytes(fence: u64) -> Vec<u8> {
    serde_json::to_vec(&EmptyManifest {
        format: 1,
        identity: [1; 16],
        generation: fence,
        capacity: 4096,
        next_id: 1,
        entries: Default::default(),
        files: Default::default(),
    })
    .unwrap()
}

struct Authority(Mutex<io::Result<Record>>);

impl Rpc for Authority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        assert_eq!(request.action, Action::Inspect);
        assert!(request.expected.is_none());
        match &*self.0.lock().unwrap() {
            Ok(record) => Ok(record.clone()),
            Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
        }
    }
}

fn descriptor(fence: u64) -> Descriptor {
    let mut hash = Sha256::new();
    hash.update(b"maki.rollback.manifest.v1\0");
    hash.update(manifest_bytes(fence));
    Descriptor {
        anchor: Anchor {
            identity: [1; 16],
            generation: fence,
            root: hash.finalize().into(),
        },
        epoch: 0,
        namespace: namespace(fence, [fence as u8; 16]),
    }
}

fn record(fence: u64) -> Record {
    Record {
        identity: [1; 16],
        current: Some(descriptor(fence)),
        fence,
        session: [fence as u8; 16],
        phase: Phase::Active,
        restore_source: None,
        last_operation: [fence as u8; 16],
    }
}

fn root() -> (tempfile::TempDir, FileBacking) {
    let dir = tempfile::tempdir().unwrap();
    let disk = FileBacking::new(dir.path()).unwrap();
    let marker = disk.open("rollback.format", true).unwrap();
    marker.write_at(0, b"MAKI-REMOTE-WITNESS-COW-V2\n").unwrap();
    marker.sync_data().unwrap();
    disk.sync_dir("").unwrap();
    (dir, disk)
}

fn populate(disk: &FileBacking, name: &str) {
    disk.create_dir_all(name).unwrap();
    let original = name.strip_prefix(".remote-gc-").unwrap_or(name);
    let fence = u64::from_str_radix(&original[7..23], 16).unwrap();
    for file in [
        "rollback.arena",
        "rollback.manifest.0",
        "rollback.manifest.1",
        "rollback.lock",
    ] {
        let data = disk.open(&format!("{name}/{file}"), true).unwrap();
        if file == "rollback.arena" {
            data.set_len(8192).unwrap();
        } else if file.starts_with("rollback.manifest.") {
            let bytes = manifest_bytes(fence);
            data.set_len((8 << 20) + 256).unwrap();
            data.write_at(0, &(bytes.len() as u64).to_le_bytes())
                .unwrap();
            data.write_at(8, &bytes).unwrap();
        }
        data.sync_data().unwrap();
    }
    disk.sync_dir(name).unwrap();
    disk.sync_dir("").unwrap();
}

fn authority(disk: &FileBacking, state: Record) -> Authority {
    if let Some(current) = &state.current {
        if !disk.exists(&current.namespace).unwrap() {
            populate(disk, &current.namespace);
        }
    }
    Authority(Mutex::new(Ok(state)))
}

#[test]
fn removes_only_quiescent_lower_fences_and_keeps_authority_root() {
    let (_dir, disk) = root();
    let old = descriptor(1).namespace;
    let live = descriptor(2).namespace;
    let current = descriptor(3).namespace;
    let future = descriptor(4).namespace;
    for name in [&old, &live, &current, &future] {
        populate(&disk, name);
    }
    let held = disk.try_lock(&format!("{live}/rollback.lock")).unwrap();
    let rpc = authority(&disk, record(3));
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert_eq!(report.removed, std::slice::from_ref(&old));
    assert_eq!(report.skipped_live, std::slice::from_ref(&live));
    assert!(!disk.exists(&old).unwrap());
    for name in [&live, &current, &future] {
        assert!(disk.exists(name).unwrap());
    }
    drop(held);
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert_eq!(report.removed, [live]);
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap()
        .removed
        .is_empty());
}

#[test]
fn restore_and_pending_fork_sources_are_retained() {
    let (_dir, disk) = root();
    let mut state = record(5);
    state.current = Some(descriptor(3));
    state.phase = Phase::RestoreClaimed;
    state.restore_source = Some(descriptor(1));
    let names: Vec<_> = (1..=6).map(|fence| descriptor(fence).namespace).collect();
    for name in &names {
        populate(&disk, name);
    }
    let rpc = authority(&disk, state);
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert_eq!(report.removed, [names[1].clone(), names[3].clone()]);
    for index in [0, 2, 4, 5] {
        assert!(disk.exists(&names[index]).unwrap());
    }
}

#[test]
fn operation_guard_excludes_a_second_process_view_of_same_pinned_root() {
    let (dir, disk) = root();
    let second = FileBacking::new(dir.path()).unwrap();
    let guard = OperationGuard::acquire(&disk).unwrap();
    assert!(
        matches!(OperationGuard::acquire(&second), Err(error) if error.kind() == io::ErrorKind::WouldBlock)
    );
    drop(guard);
    OperationGuard::acquire(&second).unwrap();
}

#[test]
fn unavailable_or_invalid_authority_cannot_delete_anything() {
    let (_dir, disk) = root();
    let old = descriptor(1).namespace;
    populate(&disk, &old);
    let rpc = Authority(Mutex::new(Err(io::Error::new(
        io::ErrorKind::TimedOut,
        "authority unavailable",
    ))));
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .is_err());
    assert!(disk.exists(&old).unwrap());
    let mut invalid = record(3);
    invalid.identity = [0; 16];
    *rpc.0.lock().unwrap() = Ok(invalid);
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .is_err());
    assert!(disk.exists(&old).unwrap());
}

#[test]
fn unexpected_contents_and_missing_original_lock_are_preserved() {
    let (_dir, disk) = root();
    let extra = descriptor(1).namespace;
    let missing_lock = descriptor(2).namespace;
    for name in [&extra, &missing_lock] {
        populate(&disk, name);
    }
    disk.open(&format!("{extra}/operator-note"), true).unwrap();
    disk.remove(&format!("{missing_lock}/rollback.lock"))
        .unwrap();
    let rpc = authority(&disk, record(3));
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(
        report.skipped_unrecognized,
        [extra.clone(), missing_lock.clone()]
    );
    for name in [&extra, &missing_lock] {
        assert!(disk.exists(&format!("{name}/rollback.arena")).unwrap());
    }
}

#[test]
fn resumes_each_durable_tombstone_unlink_prefix_without_recreating_lock() {
    let (_dir, disk) = root();
    let files = [
        "rollback.arena",
        "rollback.manifest.0",
        "rollback.manifest.1",
        "rollback.lock",
    ];
    let rpc = authority(&disk, record(10));
    for removed in 0..=files.len() {
        let original = descriptor(removed as u64 + 1).namespace;
        let retired = format!(".remote-gc-{original}");
        populate(&disk, &retired);
        for file in &files[..removed] {
            disk.remove(&format!("{retired}/{file}")).unwrap();
        }
        disk.sync_dir(&retired).unwrap();
        disk.sync_dir("").unwrap();
        let report = OperationGuard::acquire(&disk)
            .unwrap()
            .collect(&rpc)
            .unwrap();
        assert_eq!(report.removed, [original]);
        assert!(!disk.exists(&retired).unwrap());
    }
}

#[test]
fn symlinks_hardlinks_and_foreign_names_never_escape_or_partially_delete() {
    use std::os::unix::fs::symlink;
    let (dir, disk) = root();
    let outside = tempfile::tempdir().unwrap();
    let payload = outside.path().join("keep");
    std::fs::write(&payload, b"outside bytes").unwrap();
    let directory_link = descriptor(1).namespace;
    symlink(outside.path(), dir.path().join(&directory_link)).unwrap();
    let file_link = descriptor(2).namespace;
    let hardlink = descriptor(3).namespace;
    let lock_link = descriptor(4).namespace;
    for name in [&file_link, &hardlink, &lock_link] {
        populate(&disk, name);
    }
    std::fs::remove_file(dir.path().join(&file_link).join("rollback.arena")).unwrap();
    symlink(&payload, dir.path().join(&file_link).join("rollback.arena")).unwrap();
    std::fs::remove_file(dir.path().join(&hardlink).join("rollback.arena")).unwrap();
    std::fs::hard_link(&payload, dir.path().join(&hardlink).join("rollback.arena")).unwrap();
    std::fs::remove_file(dir.path().join(&lock_link).join("rollback.lock")).unwrap();
    std::fs::hard_link(&payload, dir.path().join(&lock_link).join("rollback.lock")).unwrap();
    let foreign = "remote-0000000000000001-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    populate(&disk, foreign);
    let rpc = authority(&disk, record(5));
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert!(report.removed.is_empty());
    assert_eq!(std::fs::read(&payload).unwrap(), b"outside bytes");
    for name in [&file_link, &hardlink, &lock_link] {
        assert!(disk.exists(&format!("{name}/rollback.manifest.0")).unwrap());
    }
    assert!(disk.exists(foreign).unwrap());
}

#[test]
fn pinned_root_rename_cannot_redirect_gc_to_a_replacement_directory() {
    let parent = tempfile::tempdir().unwrap();
    let original = parent.path().join("volume");
    let renamed = parent.path().join("original");
    std::fs::create_dir(&original).unwrap();
    let disk = FileBacking::new(&original).unwrap();
    let marker = disk.open("rollback.format", true).unwrap();
    marker.write_at(0, b"MAKI-REMOTE-WITNESS-COW-V2\n").unwrap();
    let old = descriptor(1).namespace;
    populate(&disk, &old);
    let guard = OperationGuard::acquire(&disk).unwrap();
    std::fs::rename(&original, &renamed).unwrap();
    let replacement = FileBacking::new(&original).unwrap();
    populate(&replacement, &old);
    let rpc = authority(&disk, record(3));
    assert_eq!(
        guard.collect(&rpc).unwrap().removed,
        std::slice::from_ref(&old)
    );
    assert!(!renamed.join(&old).exists());
    assert!(original.join(&old).join("rollback.arena").exists());
}

#[test]
fn planted_current_tombstone_and_original_collision_are_preserved() {
    let (_dir, disk) = root();
    let current = descriptor(3).namespace;
    let current_tombstone = format!(".remote-gc-{current}");
    let old = descriptor(1).namespace;
    let collision = format!(".remote-gc-{old}");
    for name in [&current, &current_tombstone, &old, &collision] {
        populate(&disk, name);
    }
    let rpc = authority(&disk, record(3));
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert!(report.removed.is_empty());
    for name in [&current, &current_tombstone, &old, &collision] {
        assert!(disk.exists(&format!("{name}/rollback.arena")).unwrap());
    }
}

#[test]
fn unlink_failure_keeps_durable_retirement_and_restarts_without_touching_current() {
    use std::os::unix::fs::PermissionsExt;
    let (dir, disk) = root();
    let old = descriptor(1).namespace;
    let current = descriptor(3).namespace;
    populate(&disk, &old);
    populate(&disk, &current);
    std::fs::set_permissions(
        dir.path().join(&old),
        std::fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let rpc = authority(&disk, record(3));
    let result = OperationGuard::acquire(&disk).unwrap().collect(&rpc);
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::PermissionDenied));
    let retired = format!(".remote-gc-{old}");
    assert!(!disk.exists(&old).unwrap());
    assert!(disk.exists(&format!("{retired}/rollback.arena")).unwrap());
    assert!(disk.exists(&format!("{current}/rollback.arena")).unwrap());
    std::fs::set_permissions(
        dir.path().join(&retired),
        std::fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    assert_eq!(
        OperationGuard::acquire(&disk)
            .unwrap()
            .collect(&rpc)
            .unwrap()
            .removed,
        [old]
    );
}

#[test]
fn operation_guard_is_exclusive_across_actual_processes() {
    const CHILD_ROOT: &str = "MAKI_GC_CHILD_ROOT";
    if let Some(root) = std::env::var_os(CHILD_ROOT) {
        let disk = FileBacking::new(root).unwrap();
        let blocked = std::env::var_os("MAKI_GC_CHILD_BLOCKED").is_some();
        match OperationGuard::acquire(&disk) {
            Ok(_) => assert!(!blocked),
            Err(error) => {
                assert!(blocked);
                assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
            }
        }
        return;
    }
    let (dir, disk) = root();
    let guard = OperationGuard::acquire(&disk).unwrap();
    let executable = std::env::current_exe().unwrap();
    let mut child = std::process::Command::new(&executable);
    child
        .args([
            "--exact",
            "operation_guard_is_exclusive_across_actual_processes",
        ])
        .env(CHILD_ROOT, dir.path())
        .env("MAKI_GC_CHILD_BLOCKED", "1");
    assert!(child.output().unwrap().status.success());
    drop(guard);
    let mut child = std::process::Command::new(executable);
    child
        .args([
            "--exact",
            "operation_guard_is_exclusive_across_actual_processes",
        ])
        .env(CHILD_ROOT, dir.path());
    assert!(child.output().unwrap().status.success());
}

#[test]
fn authority_change_aborts_before_deleting_a_newly_selected_source() {
    use std::sync::atomic::{AtomicUsize, Ordering};
    struct ChangedAuthority {
        calls: AtomicUsize,
        before: Record,
        after: Record,
    }
    impl Rpc for ChangedAuthority {
        fn call(&self, _: &Request) -> io::Result<Record> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(if call < 2 { &self.before } else { &self.after }.clone())
        }
    }
    let (_dir, disk) = root();
    let first = descriptor(1).namespace;
    let second = descriptor(2).namespace;
    populate(&disk, &first);
    populate(&disk, &second);
    let mut after = record(4);
    after.phase = Phase::Claimed;
    after.current = Some(descriptor(2));
    populate(&disk, &descriptor(3).namespace);
    let rpc = ChangedAuthority {
        calls: AtomicUsize::new(0),
        before: record(3),
        after,
    };
    let result = OperationGuard::acquire(&disk).unwrap().collect(&rpc);
    assert!(matches!(result, Err(error) if error.kind() == io::ErrorKind::WouldBlock));
    assert!(!disk.exists(&first).unwrap());
    assert!(disk.exists(&format!("{second}/rollback.arena")).unwrap());
}

#[test]
fn wrong_backing_format_and_oversized_root_fail_before_reclamation() {
    let (_dir, disk) = root();
    let old = descriptor(1).namespace;
    populate(&disk, &old);
    let marker = disk.open("rollback.format", false).unwrap();
    marker.write_at(0, b"MAKI-WITNESS-COW-V1\n").unwrap();
    let rpc = authority(&disk, record(3));
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .is_err());
    assert!(disk.exists(&old).unwrap());
    marker.write_at(0, b"MAKI-REMOTE-WITNESS-COW-V2\n").unwrap();
    for number in 0..4096 {
        disk.open(&format!("foreign-{number:04}"), true).unwrap();
    }
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .is_err());
    assert!(disk.exists(&old).unwrap());
}

#[test]
fn valid_authority_for_another_identity_cannot_reclaim_this_backing() {
    let (_dir, disk) = root();
    let old = descriptor(1).namespace;
    let newer = descriptor(5).namespace;
    populate(&disk, &old);
    populate(&disk, &newer);
    let mut foreign = record(5);
    foreign.identity = [2; 16];
    foreign.current.as_mut().unwrap().anchor.identity = [2; 16];
    foreign.validate().unwrap();
    let rpc = Authority(Mutex::new(Ok(foreign)));
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .is_err());
    assert!(disk.exists(&format!("{old}/rollback.arena")).unwrap());
}

#[test]
fn retired_namespace_with_a_live_lifetime_lock_is_never_unlinked() {
    let (_dir, disk) = root();
    let original = descriptor(1).namespace;
    let retired = format!(".remote-gc-{original}");
    populate(&disk, &retired);
    let lock = disk.try_lock(&format!("{retired}/rollback.lock")).unwrap();
    let rpc = authority(&disk, record(3));
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert_eq!(report.skipped_live, std::slice::from_ref(&retired));
    assert!(disk.exists(&format!("{retired}/rollback.arena")).unwrap());
    drop(lock);
    assert_eq!(
        OperationGuard::acquire(&disk)
            .unwrap()
            .collect(&rpc)
            .unwrap()
            .removed,
        [original]
    );
}

#[test]
fn seeded_retention_oracle_covers_live_originals_and_every_retirement_prefix() {
    use std::collections::BTreeSet;
    let (_dir, disk) = root();
    let files = [
        "rollback.arena",
        "rollback.manifest.0",
        "rollback.manifest.1",
        "rollback.lock",
    ];
    let mut seed = 0xe6a9_14d8_752e_031b_u64;
    let mut locks = Vec::new();
    let mut expected_removed = BTreeSet::new();
    let mut expected_live = BTreeSet::new();
    let mut expected_retained = BTreeSet::new();
    let current = descriptor(93);
    let source = descriptor(17);
    let mut state = record(100);
    state.phase = Phase::RestoreClaimed;
    state.current = Some(current.clone());
    state.restore_source = Some(source.clone());
    for fence in 1..=128 {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        let original = descriptor(fence).namespace;
        let retained =
            fence >= state.fence || original == current.namespace || original == source.namespace;
        let retired = !retained && seed.is_multiple_of(3);
        let entry = if retired {
            format!(".remote-gc-{original}")
        } else {
            original.clone()
        };
        populate(&disk, &entry);
        if retained {
            expected_retained.insert(entry);
            continue;
        }
        if retired {
            let prefix = (seed as usize / 3) % (files.len() + 1);
            for file in &files[..prefix] {
                disk.remove(&format!("{entry}/{file}")).unwrap();
            }
            disk.sync_dir(&entry).unwrap();
        }
        let has_lock = disk.exists(&format!("{entry}/rollback.lock")).unwrap();
        if has_lock && seed.is_multiple_of(5) {
            locks.push(disk.try_lock(&format!("{entry}/rollback.lock")).unwrap());
            expected_live.insert(entry);
        } else {
            expected_removed.insert(original);
        }
    }
    disk.sync_dir("").unwrap();
    let rpc = authority(&disk, state);
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    assert_eq!(
        report.removed.into_iter().collect::<BTreeSet<_>>(),
        expected_removed
    );
    assert_eq!(
        report.skipped_live.into_iter().collect::<BTreeSet<_>>(),
        expected_live.clone()
    );
    assert_eq!(
        report.retained.into_iter().collect::<BTreeSet<_>>(),
        expected_retained.clone()
    );
    assert!(report.skipped_unrecognized.is_empty());
    drop(locks);
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap();
    let mapped_live: BTreeSet<_> = expected_live
        .iter()
        .map(|name| name.strip_prefix(".remote-gc-").unwrap_or(name).to_owned())
        .collect();
    assert_eq!(
        report.removed.into_iter().collect::<BTreeSet<_>>(),
        mapped_live
    );
    assert_eq!(
        report.retained.into_iter().collect::<BTreeSet<_>>(),
        expected_retained
    );
    assert!(OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&rpc)
        .unwrap()
        .removed
        .is_empty());
}
