//! Audit round 4 (storage-review): #236 made `FileBacking::list` fail with
//! `InvalidData` on the first directory entry whose name is not UTF-8.
//! Recovery lists `data/` (SlotStore::open) and `journal/` (journal scan),
//! and the fast checker lists `data/`, so one stray non-UTF-8 file name in
//! either directory now makes every attach and `maki check` fail, although
//! such a name can never be a shard or segment name (those are ASCII) and
//! was ignored before. Same class as AUD-040 / AUD-078 / AUD-082.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

use maki_backing::FileBacking;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::{geometry::Geometry, init, superblock::Superblock};

fn new_volume(root: &std::path::Path) -> Arc<FileBacking> {
    let backing = Arc::new(FileBacking::new(root).unwrap());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xa4_0236),
            provider_type: "fake".into(),
            crypto_compatibility_id: "non-utf8".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 520, 1 << 20, 1 << 20).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    volume.write_ct(0, &[0x41; 520], true).unwrap();
    volume.checkpoint().unwrap();
    volume.write_ct(1, &[0x42; 520], true).unwrap();
    drop(volume);
    backing
}

fn plant(root: &std::path::Path, dir: &str, name: &[u8]) {
    let path = root.join(dir).join(OsStr::from_bytes(name));
    std::fs::write(path, b"stray").unwrap();
}

#[test]
fn control_ascii_junk_names_are_ignored() {
    let root = tempfile::tempdir().unwrap();
    let backing = new_volume(root.path());
    plant(root.path(), "data", b"notes.txt");
    plant(root.path(), "journal", b"notes.txt");
    let report = maki_format::checker::check_volume(backing.as_ref()).unwrap();
    assert!(report.ok(), "{:?}", report.errors);
    let volume = Volume::recover(backing.clone(), VolumeOptions::default()).unwrap();
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x41; 520]);
    assert_eq!(volume.read_ct(1).unwrap().unwrap().1, vec![0x42; 520]);
}

#[test]
fn non_utf8_name_in_data_dir_blocks_attach_and_check() {
    let root = tempfile::tempdir().unwrap();
    let backing = new_volume(root.path());
    // A Latin-1 name, e.g. a file restored from another system.
    plant(root.path(), "data", b"caf\xe9.bak");
    let check = maki_format::checker::check_volume(backing.as_ref());
    let recovered = Volume::recover(backing.clone(), VolumeOptions::default());
    eprintln!("fast check: {:?}", check.as_ref().map(|r| &r.errors));
    eprintln!("recover: {:?}", recovered.as_ref().err());
    assert!(
        check.as_ref().is_ok_and(|r| r.ok()),
        "fast check fails on a stray non-UTF-8 name in data/: {:?}",
        check.err()
    );
    let volume = recovered.expect("attach refuses because of a stray non-UTF-8 name in data/");
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, vec![0x41; 520]);
}

#[test]
fn non_utf8_name_in_journal_dir_blocks_attach() {
    let root = tempfile::tempdir().unwrap();
    let backing = new_volume(root.path());
    plant(root.path(), "journal", b"seg\xff.tmp");
    let recovered = Volume::recover(backing.clone(), VolumeOptions::default());
    eprintln!("recover: {:?}", recovered.as_ref().err());
    let volume = recovered.expect("attach refuses because of a stray non-UTF-8 name in journal/");
    assert_eq!(volume.read_ct(1).unwrap().unwrap().1, vec![0x42; 520]);
}
