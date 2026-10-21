#![cfg(target_os = "linux")]

use std::collections::BTreeMap;
use std::io;

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
    entries: BTreeMap<String, String>,
    files: BTreeMap<u64, String>,
}

struct Authority(Record);

impl Rpc for Authority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        assert_eq!(request.action, Action::Inspect);
        assert!(request.expected.is_none());
        Ok(self.0.clone())
    }
}

fn session(fence: u64) -> [u8; 16] {
    let mut bytes = [1; 16];
    bytes[..8].copy_from_slice(&fence.to_le_bytes());
    bytes
}

fn fixture() -> (tempfile::TempDir, FileBacking, Authority) {
    let root = tempfile::tempdir().unwrap();
    let disk = FileBacking::new(root.path()).unwrap();
    let marker = disk.open("rollback.format", true).unwrap();
    marker.write_at(0, b"MAKI-REMOTE-WITNESS-COW-V2\n").unwrap();
    marker.sync_data().unwrap();
    let fence = 5000;
    let name = namespace(fence, session(fence));
    disk.create_dir_all(&name).unwrap();
    let bytes = serde_json::to_vec(&EmptyManifest {
        format: 1,
        identity: [1; 16],
        generation: 7,
        capacity: 4096,
        next_id: 1,
        entries: BTreeMap::new(),
        files: BTreeMap::new(),
    })
    .unwrap();
    let mut hash = Sha256::new();
    hash.update(b"maki.rollback.manifest.v1\0");
    hash.update(&bytes);
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
            data.set_len((8 << 20) + 256).unwrap();
            data.write_at(0, &(bytes.len() as u64).to_le_bytes())
                .unwrap();
            data.write_at(8, &bytes).unwrap();
        }
        data.sync_data().unwrap();
    }
    disk.sync_dir(&name).unwrap();
    disk.sync_dir("").unwrap();
    let record = Record {
        identity: [1; 16],
        current: Some(Descriptor {
            anchor: Anchor {
                identity: [1; 16],
                generation: 7,
                root: hash.finalize().into(),
            },
            epoch: 0,
            namespace: name,
        }),
        fence,
        session: session(fence),
        phase: Phase::Active,
        restore_source: None,
        last_operation: [7; 16],
    };
    record.validate().unwrap();
    (root, disk, Authority(record))
}

fn abandoned_fork(disk: &FileBacking, fence: u64) -> String {
    // A physical fork creates its directory and lock before allocating the
    // arena. These recognized, quiescent remnants need no large data files.
    let name = namespace(fence, session(fence));
    disk.create_dir_all(&name).unwrap();
    drop(disk.open(&format!("{name}/rollback.lock"), true).unwrap());
    name
}

#[test]
fn control_quiescent_abandoned_fork_is_collectible() {
    let (_root, disk, authority) = fixture();
    let old = abandoned_fork(&disk, 1);
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&authority)
        .unwrap();
    assert_eq!(report.removed, std::slice::from_ref(&old));
    assert_eq!(report.counts.removed, 1);
    assert!(!report.details_truncated);
    assert!(!disk.exists(&old).unwrap());
}

#[test]
fn control_exact_directory_bound_can_reclaim_the_entire_backlog() {
    let (_root, disk, authority) = fixture();
    for fence in 1..=4093 {
        abandoned_fork(&disk, fence);
    }
    let guard = OperationGuard::acquire(&disk).unwrap();
    assert_eq!(disk.list("").unwrap().len(), 4096);
    let report = guard.collect(&authority).unwrap();
    assert_eq!(report.removed.len(), 4093);
    assert_eq!(report.counts.removed, 4093);
    assert!(!report.details_truncated);
    assert!(report.skipped_live.is_empty());
    assert!(report.skipped_unrecognized.is_empty());
    assert_eq!(disk.list("").unwrap().len(), 3);
}

#[test]
fn accumulated_quiescent_forks_must_not_permanently_disable_gc() {
    let (_root, disk, authority) = fixture();
    for fence in 1..=4094 {
        abandoned_fork(&disk, fence);
    }
    let guard = OperationGuard::acquire(&disk).unwrap();
    assert_eq!(disk.list("").unwrap().len(), 4097);
    let report = guard.collect(&authority).unwrap();
    assert_eq!(report.removed.len(), 4094);
    assert_eq!(report.counts.removed, 4094);
    assert!(!report.details_truncated);
    assert_eq!(disk.list("").unwrap().len(), 3);
    assert_eq!(guard.collect(&authority).unwrap().counts.removed, 0);
}

#[test]
fn tombstones_and_forks_cross_pages_and_report_all_removals() {
    let (root, disk, authority) = fixture();
    // Mixed creation order and both sides of the tombstone rename boundary.
    for fence in (1..=4100).rev() {
        let name = abandoned_fork(&disk, fence);
        if fence % 2 == 0 {
            std::fs::rename(
                root.path().join(&name),
                root.path().join(format!(".remote-gc-{name}")),
            )
            .unwrap();
        }
    }
    let guard = OperationGuard::acquire(&disk).unwrap();
    let report = guard.collect(&authority).unwrap();
    assert_eq!(report.counts.removed, 4100);
    assert_eq!(report.removed.len(), 4096);
    assert!(report.details_truncated);
    assert_eq!(disk.list("").unwrap().len(), 3);
    assert_eq!(guard.collect(&authority).unwrap().counts.removed, 0);
}

#[test]
fn unrecognized_page_does_not_starve_later_candidates_or_grow_report() {
    let (_root, disk, authority) = fixture();
    for index in (0..4100).rev() {
        disk.open(&format!("foreign-{index:04}"), true).unwrap();
    }
    let old = abandoned_fork(&disk, 1);
    let guard = OperationGuard::acquire(&disk).unwrap();
    let report = guard.collect(&authority).unwrap();
    assert_eq!(report.removed, std::slice::from_ref(&old));
    assert_eq!(report.counts.removed, 1);
    assert!(!disk.exists(&old).unwrap());
    assert_eq!(report.counts.skipped_unrecognized, 4100);
    assert_eq!(report.skipped_unrecognized.len(), 4096);
    assert_eq!(report.skipped_unrecognized.first().unwrap(), "foreign-0000");
    assert_eq!(report.skipped_unrecognized.last().unwrap(), "foreign-4095");
    assert!(report.details_truncated);
    assert_eq!(disk.list("").unwrap().len(), 4103);
}

#[test]
fn all_retained_pages_terminate_with_bounded_details() {
    let (_root, disk, authority) = fixture();
    for fence in 5001..=9100 {
        abandoned_fork(&disk, fence);
    }
    let report = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&authority)
        .unwrap();
    assert_eq!(report.counts.retained, 4101);
    assert_eq!(report.retained.len(), 4096);
    assert_eq!(report.counts.removed, 0);
    assert!(report.details_truncated);
    assert_eq!(disk.list("").unwrap().len(), 4103);
}

#[test]
fn authority_is_rechecked_before_retiring_a_candidate_on_a_later_page() {
    use std::sync::atomic::{AtomicBool, Ordering};

    struct ChangedAuthority {
        record: Record,
        inspected: AtomicBool,
    }
    impl Rpc for ChangedAuthority {
        fn call(&self, request: &Request) -> io::Result<Record> {
            assert_eq!(request.action, Action::Inspect);
            let mut record = self.record.clone();
            if self.inspected.swap(true, Ordering::SeqCst) {
                record.fence += 1;
                record.phase = Phase::Claimed;
            }
            record.validate().unwrap();
            Ok(record)
        }
    }
    let (_root, disk, authority) = fixture();
    for index in 0..4096 {
        disk.open(&format!("foreign-{index:04}"), true).unwrap();
    }
    let old = abandoned_fork(&disk, 1);
    let changed = ChangedAuthority {
        record: authority.0,
        inspected: AtomicBool::new(false),
    };
    let error = OperationGuard::acquire(&disk)
        .unwrap()
        .collect(&changed)
        .unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    assert_eq!(error.to_string(), "GC authority changed");
    assert!(disk.exists(&old).unwrap());
}
