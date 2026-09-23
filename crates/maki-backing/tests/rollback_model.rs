#![cfg(target_os = "linux")]

use maki_backing::{Backing, BackingFile, RollbackBacking};
use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::FileExt;
use std::sync::Arc;

const PAGE: usize = 4096;
const PAGES: usize = 8;
const CAPACITY: usize = PAGE * PAGES;

fn dirs() -> (tempfile::TempDir, tempfile::TempDir) {
    (
        tempfile::tempdir().unwrap(),
        tempfile::tempdir_in("/dev/shm").unwrap(),
    )
}

#[derive(Clone, Default)]
struct Image {
    bytes: Vec<u8>,
    reserved: BTreeSet<usize>,
}

impl Image {
    fn reserve(&mut self, offset: usize, len: usize) {
        if len == 0 {
            return;
        }
        let end = offset + len;
        self.reserved.extend(offset / PAGE..end.div_ceil(PAGE));
        self.bytes.resize(self.bytes.len().max(end), 0);
    }

    fn write(&mut self, offset: usize, data: &[u8]) {
        self.reserve(offset, data.len());
        self.bytes[offset..offset + data.len()].copy_from_slice(data);
    }

    fn set_len(&mut self, len: usize) {
        self.bytes.resize(len, 0);
        self.reserved.retain(|page| *page < len.div_ceil(PAGE));
    }

    fn punch(&mut self, offset: usize, len: usize) {
        let end = (offset + len).min(self.bytes.len());
        if offset >= end {
            return;
        }
        self.bytes[offset..end].fill(0);
        let mut at = offset;
        while at < end {
            let count = (PAGE - at % PAGE).min(end - at);
            if at.is_multiple_of(PAGE) && count == PAGE {
                self.reserved.remove(&(at / PAGE));
            }
            at += count;
        }
    }
}

fn reserve_operation(working: &mut Image, durable: &mut Image, offset: usize, len: usize) {
    if len == 0 {
        return;
    }
    let end = offset + len;
    let adds_durable_page =
        (offset / PAGE..end.div_ceil(PAGE)).any(|page| !durable.reserved.contains(&page));
    if adds_durable_page {
        durable.reserve(offset, len);
    }
    working.reserve(offset, len);
}

struct Lcg(u64);

impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self
            .0
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1_442_695_040_888_963_407);
        self.0
    }

    fn below(&mut self, limit: usize) -> usize {
        ((self.next() >> 32) as usize) % limit
    }
}

fn assert_image(
    backing: &RollbackBacking,
    file: &Arc<dyn BackingFile>,
    working: &Image,
    durable: &Image,
    seed: u64,
    step: usize,
) {
    assert_eq!(
        file.len().unwrap(),
        working.bytes.len() as u64,
        "length mismatch seed={seed:#x} step={step}"
    );
    let mut actual = vec![0; working.bytes.len()];
    file.read_at(0, &mut actual).unwrap();
    assert_eq!(
        actual, working.bytes,
        "contents mismatch seed={seed:#x} step={step}"
    );
    let occupied = working.reserved.union(&durable.reserved).count();
    assert_eq!(
        backing.free_bytes().unwrap(),
        Some((CAPACITY - occupied * PAGE) as u64),
        "free-space mismatch seed={seed:#x} step={step}"
    );
}

#[test]
fn deterministic_state_machine_matches_independent_file_oracle() {
    const SEEDS: [u64; 16] = [
        0x01,
        0x02,
        0x03,
        0x04,
        0x10,
        0x20,
        0x30,
        0x40,
        0x1234,
        0x5678,
        0x9abc,
        0xdef0,
        0x1357_9bdf,
        0x2468_ace0,
        0xdead_beef,
        0xcafe_f00d,
    ];

    let mut operation_counts = [0usize; 8];
    for seed in SEEDS {
        let (root, witness) = dirs();
        let mut backing =
            RollbackBacking::create(root.path(), witness.path(), CAPACITY as u64).unwrap();
        let mut file = backing.open("model", true).unwrap();
        backing.sync_dir("").unwrap();
        let mut working = Image::default();
        let mut durable = Image::default();
        let mut rng = Lcg(seed);

        for step in 0..100 {
            let operation = rng.below(8);
            operation_counts[operation] += 1;
            match operation {
                0 => {
                    let offset = rng.below(CAPACITY);
                    let len = 1 + rng.below((CAPACITY - offset).min(PAGE + 97));
                    let data: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
                    file.write_at(offset as u64, &data).unwrap();
                    // RollbackBacking reserves first, which may durably expose
                    // a longer zero-filled EOF without publishing these bytes.
                    reserve_operation(&mut working, &mut durable, offset, len);
                    working.write(offset, &data);
                }
                1 => {
                    let len = rng.below(CAPACITY + 1);
                    file.set_len(len as u64).unwrap();
                    working.set_len(len);
                }
                2 => {
                    let offset = rng.below(CAPACITY + 1);
                    let len = rng.below(CAPACITY - offset + 1);
                    file.allocate_range(offset as u64, len as u64).unwrap();
                    reserve_operation(&mut working, &mut durable, offset, len);
                }
                3 => {
                    let offset = rng.below(CAPACITY + 1);
                    let len = rng.below(CAPACITY - offset + 1);
                    file.punch_hole(offset as u64, len as u64).unwrap();
                    working.punch(offset, len);
                }
                4 => {
                    file.sync_data().unwrap();
                    durable = working.clone();
                }
                5 => {
                    drop(file);
                    drop(backing);
                    backing = RollbackBacking::open(root.path(), witness.path()).unwrap();
                    file = backing.open("model", false).unwrap();
                    working = durable.clone();
                }
                6 => {
                    let offset = rng.below(CAPACITY);
                    let len = 1 + rng.below(CAPACITY - offset);
                    file.allocate_range(offset as u64, len as u64).unwrap();
                    file.allocate_range(offset as u64, len as u64).unwrap();
                    reserve_operation(&mut working, &mut durable, offset, len);
                }
                7 => {
                    file.allocate_range(0, CAPACITY as u64).unwrap();
                    reserve_operation(&mut working, &mut durable, 0, CAPACITY);
                    assert_eq!(backing.free_bytes().unwrap(), Some(0));
                    assert_eq!(
                        file.allocate_range(CAPACITY as u64, 1)
                            .unwrap_err()
                            .raw_os_error(),
                        Some(28),
                        "capacity error mismatch seed={seed:#x} step={step}"
                    );
                }
                _ => unreachable!(),
            }
            assert_image(&backing, &file, &working, &durable, seed, step);
        }
    }
    for (operation, count) in operation_counts.into_iter().enumerate() {
        assert!(
            count > 0,
            "operation category {operation} was not exercised"
        );
    }
}

#[test]
fn removed_open_identity_cannot_redirect_a_recreated_name() {
    let (root, witness) = dirs();
    let backing = RollbackBacking::create(root.path(), witness.path(), CAPACITY as u64).unwrap();
    let old = backing.open("same", true).unwrap();
    old.write_at(0, b"old").unwrap();
    old.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    backing.remove("same").unwrap();
    let new = backing.open("same", true).unwrap();
    new.write_at(0, b"new").unwrap();
    new.sync_data().unwrap();
    old.write_at(0, b"stale").unwrap();
    old.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    let mut bytes = [0; 3];
    new.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"new");
    drop((old, new, backing));

    let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
    let file = reopened.open("same", false).unwrap();
    file.read_at(0, &mut bytes).unwrap();
    assert_eq!(&bytes, b"new");
}

#[test]
fn deleted_file_capacity_is_reclaimed_after_commit_and_last_handle_drop() {
    let (root, witness) = dirs();
    let backing = RollbackBacking::create(root.path(), witness.path(), PAGE as u64).unwrap();
    let old = backing.open("old", true).unwrap();
    old.write_at(0, &[0x44; PAGE]).unwrap();
    old.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    backing.remove("old").unwrap();
    backing.sync_dir("").unwrap();
    // The namespace deletion is committed and no handle now needs the old
    // identity, so its sole arena page is available to a replacement file.
    drop(old);
    let replacement = backing.open("replacement", true).unwrap();
    replacement.write_at(0, &[0x55; PAGE]).unwrap();
    replacement.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    drop((replacement, backing));
    let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
    let replacement = reopened.open("replacement", false).unwrap();
    let mut bytes = vec![0; PAGE];
    replacement.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, vec![0x55; PAGE]);
}

#[test]
fn unlink_reclamation_obeys_namespace_and_handle_boundaries() {
    // Closing after an uncommitted unlink cannot reclaim the file selected by
    // the durable namespace. A restart must recover both its name and bytes.
    let (root, witness) = dirs();
    let backing = RollbackBacking::create(root.path(), witness.path(), PAGE as u64).unwrap();
    let old = backing.open("old", true).unwrap();
    old.write_at(0, &[0x31; PAGE]).unwrap();
    old.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    backing.remove("old").unwrap();
    drop(old);
    assert_eq!(backing.free_bytes().unwrap(), Some(0));
    let replacement = backing.open("replacement", true).unwrap();
    assert_eq!(
        replacement
            .write_at(0, &[0x91; PAGE])
            .unwrap_err()
            .raw_os_error(),
        Some(28)
    );
    drop((replacement, backing));

    let reopened = RollbackBacking::open(root.path(), witness.path()).unwrap();
    assert_eq!(reopened.free_bytes().unwrap(), Some(0));
    let old = reopened.open("old", false).unwrap();
    let mut bytes = vec![0; PAGE];
    old.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, vec![0x31; PAGE]);
    drop((old, reopened));

    // A committed unlink still retains the identity while a handle can read
    // it. Once that final handle closes, the next space query may safely
    // publish reclamation and report the page available.
    let (root, witness) = dirs();
    let backing = RollbackBacking::create(root.path(), witness.path(), PAGE as u64).unwrap();
    let old = backing.open("old", true).unwrap();
    old.write_at(0, &[0x73; PAGE]).unwrap();
    old.sync_data().unwrap();
    backing.sync_dir("").unwrap();
    backing.remove("old").unwrap();
    backing.sync_dir("").unwrap();
    assert_eq!(backing.free_bytes().unwrap(), Some(0));
    old.read_at(0, &mut bytes).unwrap();
    assert_eq!(bytes, vec![0x73; PAGE]);
    drop(old);
    assert_eq!(backing.free_bytes().unwrap(), Some(PAGE as u64));
}

#[test]
fn replaying_old_valid_arena_bytes_under_current_witness_is_rejected() {
    let (root, witness) = dirs();
    let backing = RollbackBacking::create(root.path(), witness.path(), CAPACITY as u64).unwrap();
    let file = backing.open("data", true).unwrap();
    file.write_at(0, &[0x19; PAGE]).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();

    let arena_path = root.path().join("rollback.arena");
    let old_arena = fs::read(&arena_path).unwrap();
    file.write_at(0, &[0x91; PAGE]).unwrap();
    file.sync_data().unwrap();
    drop((file, backing));

    let arena = fs::OpenOptions::new().write(true).open(arena_path).unwrap();
    arena.write_all_at(&old_arena, 0).unwrap();
    arena.sync_data().unwrap();
    assert_eq!(
        RollbackBacking::open(root.path(), witness.path())
            .err()
            .unwrap()
            .kind(),
        io::ErrorKind::InvalidData
    );
}
