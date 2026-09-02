//! End-to-end test of `maki-check` as a real process against a real
//! filesystem volume: passes on a fresh volume, survives one corrupt
//! superblock copy (A/B fallback), and fails closed when both are corrupt
//! or the root is not a volume.

use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Output};

use maki_backing::FileBacking;
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;

fn run(root: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-check"))
        .arg(root)
        .output()
        .expect("spawn maki-check")
}

fn scribble(path: &str, offset: u64) {
    let mut f = std::fs::OpenOptions::new().write(true).open(path).unwrap();
    f.seek(SeekFrom::Start(offset)).unwrap();
    f.write_all(&[0xFF; 16]).unwrap();
}

#[test]
fn check_passes_then_fails_closed_on_corruption() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let backing = FileBacking::new(&root).unwrap();
    init::create_volume(
        &backing,
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xE2E),
            provider_type: "local-aes-gcm-siv".into(),
            crypto_compatibility_id: "local-aes-gcm-siv-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(4096, 4096, 512, 4384, 1 << 20, 64 << 10).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();

    let out = run(&root);
    assert!(
        out.status.success(),
        "fresh volume must pass: {}",
        String::from_utf8_lossy(&out.stdout)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("check passed"));

    scribble(&format!("{root}/superblock.a"), 100);
    let out = run(&root);
    assert!(out.status.success(), "one corrupt copy must fall back");

    scribble(&format!("{root}/superblock.b"), 100);
    let out = run(&root);
    assert!(!out.status.success(), "both corrupt: must fail");
    assert!(String::from_utf8_lossy(&out.stdout).contains("check FAILED"));
}

#[test]
fn check_rejects_a_root_that_is_not_a_volume() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty").to_string_lossy().into_owned();
    std::fs::create_dir_all(&empty).unwrap();
    let out = run(&empty);
    assert!(!out.status.success(), "empty root must not pass");
}
