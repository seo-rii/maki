//! Recovery and both checks look in `data/` and `journal/` only for the
//! volume's own file names, which are ASCII, and ignore every other entry.
//! An entry there whose name is not UTF-8 (a Latin-1 name restored from
//! another system, an editor's backup) made the directory listing fail with
//! `InvalidData` instead, so one such file made every attach, the recovery
//! coordinator, `maki check` and `maki check --deep` fail on a plain
//! `FileBacking` volume. Such an entry can never be a volume file: it is
//! skipped like any other unknown name, and nothing reads, writes, renames
//! or removes it.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::checker::check_volume;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};

const CT_LEN: usize = 540;
const SEGMENT: u64 = 4096;
const UNITS_PER_SHARD: u64 = 64;
/// One checkpointed unit in each of these shards, so `data/` holds several
/// shard files.
const SHARDS: u64 = 8;
/// Units 1..=JOURNALED are newer than the checkpoint, and so is unit 0's
/// second value: their records span several journal segments.
const JOURNALED: u64 = 24;
const STRAY: &[u8] = b"not a volume file";

fn geometry() -> Geometry {
    Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * UNITS_PER_SHARD).unwrap()
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; CT_LEN]
}

/// The value each written unit holds.
fn expected() -> Vec<(u64, Vec<u8>)> {
    let mut units = vec![(0, ct(0xA0))];
    units.extend((1..SHARDS).map(|shard| (shard * UNITS_PER_SHARD, ct(shard as u8))));
    units.extend((1..=JOURNALED).map(|unit| (unit, ct(0x40 + unit as u8))));
    units
}

fn recover(backing: &Arc<FileBacking>) -> Volume {
    Volume::recover(
        backing.clone() as Arc<dyn Backing>,
        VolumeOptions {
            journal_segment_size: SEGMENT,
        },
    )
    .unwrap_or_else(|error| panic!("attach refused: {error:?}"))
}

fn new_volume(root: &Path) -> Arc<FileBacking> {
    let backing = Arc::new(FileBacking::new(root).unwrap());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x0f8_a1e5),
            provider_type: "fake".into(),
            crypto_compatibility_id: "non-utf8-entries".into(),
            key_identity: "k".into(),
            geometry: geometry(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = recover(&backing);
    for shard in 0..SHARDS {
        volume
            .write_ct(shard * UNITS_PER_SHARD, &ct(shard as u8), true)
            .unwrap();
    }
    volume.checkpoint().unwrap();
    volume.write_ct(0, &ct(0xA0), true).unwrap();
    for unit in 1..=JOURNALED {
        volume.write_ct(unit, &ct(0x40 + unit as u8), true).unwrap();
    }
    drop(volume);
    backing
}

fn segments(root: &Path) -> usize {
    std::fs::read_dir(root.join("journal"))
        .unwrap()
        .filter(|entry| {
            let name = entry.as_ref().unwrap().file_name();
            name.to_str()
                .and_then(layout::parse_journal_segment)
                .is_some()
        })
        .count()
}

/// Create files named `names` in `dir`; return their paths.
fn plant(root: &Path, dir: &str, names: &[Vec<u8>]) -> Vec<PathBuf> {
    names
        .iter()
        .map(|name| {
            let path = root.join(dir).join(OsStr::from_bytes(name));
            std::fs::write(&path, STRAY).unwrap();
            path
        })
        .collect()
}

/// Names that are not UTF-8, some resembling a volume file's name, and
/// enough of them that a scan almost certainly meets some before the
/// volume's own names, whatever order the filesystem returns entries in.
fn non_utf8_names(resembling: &[&[u8]]) -> Vec<Vec<u8>> {
    let mut names: Vec<Vec<u8>> = resembling.iter().map(|name| name.to_vec()).collect();
    names.extend((0..16u8).map(|i| [&b"stray-"[..], &[b'a' + i, 0xFF]].concat()));
    names
}

fn assert_checks_pass(backing: &Arc<FileBacking>) {
    let fast = check_volume(backing.as_ref())
        .unwrap_or_else(|error| panic!("the fast check is inconclusive: {error:?}"));
    assert!(fast.ok(), "the fast check fails: {:?}", fast.errors);
    let deep = deep_check(backing.clone() as Arc<dyn Backing>, SEGMENT)
        .unwrap_or_else(|error| panic!("the deep check is inconclusive: {error:?}"));
    assert!(deep.ok(), "the deep check fails: {:?}", deep.errors);
}

fn assert_volume_serves_every_value(backing: &Arc<FileBacking>) {
    let mut volume = recover(backing);
    for (unit, value) in expected() {
        assert_eq!(
            volume.read_ct(unit).unwrap().unwrap().1,
            value,
            "unit {unit}"
        );
    }
    // The volume keeps working: a checkpoint consumes the journal and
    // writes into the shard files, and the next attach finds both.
    volume.checkpoint().unwrap();
    volume.write_ct(2, &ct(0xEE), true).unwrap();
    drop(volume);
    let volume = recover(backing);
    assert_eq!(volume.read_ct(2).unwrap().unwrap().1, ct(0xEE));
    assert_eq!(volume.read_ct(0).unwrap().unwrap().1, ct(0xA0));
}

fn assert_untouched(strays: &[PathBuf]) {
    for path in strays {
        assert_eq!(
            std::fs::read(path).unwrap(),
            STRAY,
            "{path:?} was changed or removed"
        );
    }
}

/// A volume whose `data/` holds shard files and, beside them, entries whose
/// names are not UTF-8.
fn data_directory_fixture() -> (tempfile::TempDir, Arc<FileBacking>, Vec<PathBuf>) {
    let root = tempfile::tempdir().unwrap();
    let backing = new_volume(root.path());
    for shard in 0..SHARDS {
        assert!(backing.exists(&layout::shard_data(shard)).unwrap());
    }
    let strays = plant(
        root.path(),
        "data",
        &non_utf8_names(&[b"caf\xe9.bak", b"shard-0000000\xff.dat", b"shard-\x80"]),
    );
    (root, backing, strays)
}

/// A volume whose `journal/` holds several segments and, beside them,
/// entries whose names are not UTF-8.
fn journal_directory_fixture() -> (tempfile::TempDir, Arc<FileBacking>, Vec<PathBuf>) {
    let root = tempfile::tempdir().unwrap();
    let backing = new_volume(root.path());
    assert!(
        segments(root.path()) > 2,
        "the journaled values must span several segments"
    );
    let strays = plant(
        root.path(),
        "journal",
        &non_utf8_names(&[b"seg\xff.tmp", b"seg-000000000000000\xff", b"seg-\x80"]),
    );
    (root, backing, strays)
}

#[test]
fn attach_skips_non_utf8_names_in_the_data_directory() {
    let (_root, backing, strays) = data_directory_fixture();
    assert_volume_serves_every_value(&backing);
    assert_untouched(&strays);
}

#[test]
fn checks_skip_non_utf8_names_in_the_data_directory() {
    let (_root, backing, strays) = data_directory_fixture();
    assert_checks_pass(&backing);
    assert_untouched(&strays);
}

#[test]
fn attach_skips_non_utf8_names_in_the_journal_directory() {
    let (_root, backing, strays) = journal_directory_fixture();
    assert_volume_serves_every_value(&backing);
    assert_untouched(&strays);
}

#[test]
fn checks_skip_non_utf8_names_in_the_journal_directory() {
    let (_root, backing, strays) = journal_directory_fixture();
    assert_checks_pass(&backing);
    assert_untouched(&strays);
}

/// Control: other names that are not volume files, including ones that
/// only resemble a shard or segment name, were ignored before and still are.
#[test]
fn control_ascii_names_that_are_not_volume_files_are_ignored() {
    let root = tempfile::tempdir().unwrap();
    let backing = new_volume(root.path());
    let mut strays = plant(
        root.path(),
        "data",
        &[b"notes.txt".to_vec(), b"shard-1.dat".to_vec()],
    );
    strays.extend(plant(
        root.path(),
        "journal",
        &[b"notes.txt".to_vec(), b"seg-1".to_vec()],
    ));
    assert_checks_pass(&backing);
    assert_volume_serves_every_value(&backing);
    assert_checks_pass(&backing);
    assert_untouched(&strays);
}
