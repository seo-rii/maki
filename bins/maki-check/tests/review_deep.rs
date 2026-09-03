//! Review M-018: `maki-check --deep` as a real process finds slot damage on
//! a real filesystem that the fast check reports as passing.

use std::io::{Seek, SeekFrom, Write};
use std::process::{Command, Output};
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_maki-check"))
        .args(args)
        .output()
        .expect("spawn maki-check")
}

fn stdout(out: &Output) -> String {
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn deep_check_finds_slot_damage_on_a_real_volume() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("vol").to_string_lossy().into_owned();
    let geometry = Geometry::compute(512, 512, 512, 544, 1 << 20, 64 << 10).unwrap();
    let backing = Arc::new(FileBacking::new(&root).unwrap());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0xDEE9),
            provider_type: "local-aes-gcm-siv".into(),
            crypto_compatibility_id: "local-aes-gcm-siv-v1".into(),
            key_identity: "k".into(),
            geometry: geometry.clone(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    {
        let mut vol = Volume::recover(
            backing.clone() as Arc<dyn Backing>,
            VolumeOptions {
                journal_segment_size: 4096,
            },
        )
        .unwrap();
        vol.write_ct(3, &vec![0x11; 540], true).unwrap();
        vol.checkpoint().unwrap();
    }

    let out = run(&[&root, "--deep"]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(
        stdout(&out).contains("slots: 1 allocated, 0 invalid"),
        "{}",
        stdout(&out)
    );

    // Damage the slot payload on disk.
    let (shard, idx) = geometry.shard_of_unit(3);
    let path = format!("{root}/{}", layout::shard_data(shard));
    let mut f = std::fs::OpenOptions::new().write(true).open(&path).unwrap();
    f.seek(SeekFrom::Start(geometry.slot_offset(idx) + 64 + 7))
        .unwrap();
    f.write_all(&[0xFF; 8]).unwrap();
    drop(f);

    let fast = run(&[&root]);
    assert!(fast.status.success(), "fast check cannot see slot payloads");
    let deep = run(&[&root, "--deep"]);
    assert!(!deep.status.success(), "{}", stdout(&deep));
    assert!(stdout(&deep).contains("unit 3"), "{}", stdout(&deep));
    assert!(stdout(&deep).contains("check FAILED"));
}

#[test]
fn deep_check_rejects_unknown_flags() {
    let out = run(&["/tmp/whatever", "--bogus"]);
    assert_eq!(out.status.code(), Some(2));
}
