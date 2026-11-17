//! audit2 (decoder-fuzz): GC tombstone / namespace NAME parsing in a remote
//! rollback root, driven through the public `OperationGuard::collect`.
//!
//! Names in the root are untrusted input to GC: anyone who can write the
//! backing root can add entries. Properties: no panic for any 56-byte name
//! (including multi-byte UTF-8 placed across the parser's fixed byte
//! offsets), unrecognized names are skipped and reported, and a stray entry
//! never stops GC from retiring the legitimately retired namespaces.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::panic::{catch_unwind, AssertUnwindSafe};
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

struct Authority(Mutex<Record>);
impl Rpc for Authority {
    fn call(&self, request: &Request) -> io::Result<Record> {
        assert_eq!(request.action, Action::Inspect);
        Ok(self.0.lock().unwrap().clone())
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

fn populate(disk: &FileBacking, name: &str, fence: u64) {
    disk.create_dir_all(name).unwrap();
    for file in ["rollback.arena", "rollback.manifest.0", "rollback.manifest.1", "rollback.lock"] {
        let data = disk.open(&format!("{name}/{file}"), true).unwrap();
        if file == "rollback.arena" {
            data.set_len(8192).unwrap();
        } else if file.starts_with("rollback.manifest.") {
            let bytes = manifest_bytes(fence);
            data.set_len((8 << 20) + 256).unwrap();
            data.write_at(0, &(bytes.len() as u64).to_le_bytes()).unwrap();
            data.write_at(8, &bytes).unwrap();
        }
        data.sync_data().unwrap();
    }
    disk.sync_dir(name).unwrap();
    disk.sync_dir("").unwrap();
}

/// 56-byte names that are almost namespaces.
fn odd_names() -> Vec<String> {
    let base = namespace(1, [0xab; 16]);
    let mut out = Vec::new();
    for ch in ["é", "€", "𝄞"] {
        for at in [0usize, 5, 6, 7, 8, 21, 22, 23, 24, 25, 53, 54] {
            let mut s = base.clone();
            let w = ch.len();
            if at + w <= s.len() && s.is_char_boundary(at) && s.is_char_boundary(at + w) {
                s.replace_range(at..at + w, ch);
                out.push(s.clone());
                out.push(format!(".remote-gc-{s}"));
            }
        }
    }
    out.push(base.to_uppercase());
    out.push(namespace(0, [0xab; 16]));
    out.push(namespace(1, [0; 16]));
    out.push(format!("{base}0"));
    out.push(base[..55].to_string());
    out.push(".remote-gc-".to_string());
    out.push(".remote-gc-.remote-gc-".to_string() + &base);
    out
}

#[test]
fn odd_root_entries_never_panic_and_are_reported_unrecognized() {
    let mut failures = Vec::new();
    for name in odd_names() {
        let (_dir, disk) = root();
        let current = descriptor(3).namespace;
        populate(&disk, &current, 3);
        let old = descriptor(1).namespace;
        populate(&disk, &old, 1);
        if disk.create_dir_all(&name).is_err() {
            continue;
        }
        let rpc = Authority(Mutex::new(record(3)));
        let guard = OperationGuard::acquire(&disk).unwrap();
        match catch_unwind(AssertUnwindSafe(|| guard.collect(&rpc))) {
            Err(_) => failures.push(format!("{name:?}: collect panicked")),
            Ok(Err(e)) => failures.push(format!("{name:?}: collect failed: {e}")),
            Ok(Ok(report)) => {
                if !report.removed.contains(&old) {
                    failures.push(format!("{name:?}: the retired namespace was not collected"));
                }
            }
        }
    }
    assert!(failures.is_empty(), "{failures:#?}");
}

/// A single non-UTF-8 entry anywhere in the remote root (any writer of the
/// backing root can create one) makes every GC pass fail with InvalidData,
/// so no retired namespace is ever reclaimed again.
#[test]
fn a_non_utf8_root_entry_blocks_all_reclamation() {
    let (dir, disk) = root();
    let current = descriptor(3).namespace;
    populate(&disk, &current, 3);
    let old = descriptor(1).namespace;
    populate(&disk, &old, 1);
    std::fs::create_dir(dir.path().join(std::ffi::OsStr::from_bytes(b"stray-\xff"))).unwrap();
    let rpc = Authority(Mutex::new(record(3)));
    let guard = OperationGuard::acquire(&disk).unwrap();
    let result = guard.collect(&rpc);
    let still_there = disk.exists(&old).unwrap();
    eprintln!(
        "collect: {:?}; retired namespace still present: {still_there}",
        result.as_ref().map(|r| r.counts.removed).map_err(|e| e.to_string())
    );
    assert!(
        result.is_ok() && !still_there,
        "a non-UTF-8 root entry stopped GC: {:?}",
        result.err()
    );
}
