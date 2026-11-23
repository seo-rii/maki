//! The fast check looks in `data/` only for shard data file names, which are
//! ASCII, and ignores every other entry. An entry whose name is not UTF-8
//! made the directory listing fail with `InvalidData` instead, so `maki
//! check` was inconclusive on a plain `FileBacking` volume that held one.
//! It is skipped like any other unknown name. Volume creation must still
//! account for every entry: it proves the layout directories empty, and an
//! entry that is not UTF-8 still refuses the root.
#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use maki_backing::{Backing, FileBacking};
use maki_format::checker::check_volume;
use maki_format::geometry::Geometry;
use maki_format::init::create_volume;
use maki_format::layout;
use maki_format::superblock::Superblock;

const STRAY: &[u8] = b"not a volume file";

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: uuid::Uuid::from_u128(0x0f8_a1e6),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 1024, 512, 1032, 16 * 1024, 8 * 1024).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn plant(root: &Path, dir: &str, name: &[u8]) -> PathBuf {
    let path = root.join(dir).join(OsStr::from_bytes(name));
    std::fs::write(&path, STRAY).unwrap();
    path
}

#[test]
fn fast_check_skips_non_utf8_names_and_still_finds_an_uncataloged_shard() {
    let root = tempfile::tempdir().unwrap();
    let backing = FileBacking::new(root.path()).unwrap();
    create_volume(&backing, superblock()).unwrap();
    // A shard data file the catalog does not list (a crash between its
    // creation and the catalog commit): the check must still find it
    // whatever order the directory returns its entries in.
    backing.open(&layout::shard_data(1), true).unwrap();
    let mut strays = vec![
        plant(root.path(), "data", b"caf\xe9.bak"),
        plant(root.path(), "data", b"shard-0000000\xff.dat"),
        plant(root.path(), "data", b"notes.txt"),
    ];
    strays.extend((0..16u8).map(|i| plant(root.path(), "data", &[b'a' + i, 0xFF])));
    let report = check_volume(&backing)
        .unwrap_or_else(|error| panic!("the check is inconclusive: {error:?}"));
    assert!(report.ok(), "{:?}", report.errors);
    let uncataloged: Vec<_> = report
        .warnings
        .iter()
        .filter(|warning| warning.starts_with("shard data file "))
        .collect();
    assert_eq!(
        uncataloged,
        ["shard data file shard-00000001.dat (index 1) is not in the catalog; recovery adopts it"],
        "{:?}",
        report.warnings
    );
    for path in strays {
        assert_eq!(std::fs::read(&path).unwrap(), STRAY, "{path:?}");
    }
}

/// Control: creation proves each layout directory empty, so an entry whose
/// name is not UTF-8 still refuses the root, and nothing is written into it.
#[test]
fn control_creation_still_refuses_a_non_utf8_entry_in_a_layout_directory() {
    for dir in [
        layout::DATA_DIR,
        layout::JOURNAL_DIR,
        layout::CHECKPOINT_DIR,
    ] {
        let root = tempfile::tempdir().unwrap();
        let backing = FileBacking::new(root.path()).unwrap();
        backing.create_dir_all(dir).unwrap();
        let stray = plant(root.path(), dir, b"caf\xe9.bak");
        let error = create_volume(&backing, superblock())
            .expect_err("a root holding an earlier entry was initialized");
        assert!(
            matches!(&error, maki_format::error::FormatError::Io(error)
                if error.kind() == std::io::ErrorKind::InvalidData),
            "{dir}: {error:?}"
        );
        for name in layout::ROOT_METADATA {
            assert!(!backing.exists(name).unwrap(), "{dir}: {name} was written");
        }
        assert_eq!(std::fs::read(&stray).unwrap(), STRAY, "{dir}");
    }
}
