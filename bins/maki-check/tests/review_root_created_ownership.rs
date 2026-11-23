//! `maki-check --deep` takes the volume lock, creating `volume.lock` when a
//! restore or copy dropped the empty file. Run as root on a volume the
//! daemon user owns, it must create the lock for that user, or the daemon
//! can no longer take it. Running the checker as another user needs root:
//! without it this test prints why it is skipped.
#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, Output};
use std::sync::Arc;

use maki_backing::{Backing, FileBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;

/// Stands in for the daemon user. Distinct uid and gid, neither root's.
const DAEMON: (u32, u32) = (65534, 65533);

fn run(args: &[&str], user: Option<(u32, u32)>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_maki-check"));
    command.args(args);
    if let Some((uid, gid)) = user {
        command.uid(uid).gid(gid);
    }
    command.output().expect("spawn maki-check")
}

fn succeeded(what: &str, output: &Output) {
    assert!(
        output.status.success(),
        "{what} failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn give(path: &Path, (uid, gid): (u32, u32)) {
    std::os::unix::fs::lchown(path, Some(uid), Some(gid)).unwrap();
    if fs::symlink_metadata(path).unwrap().is_dir() {
        for entry in fs::read_dir(path).unwrap() {
            give(&entry.unwrap().path(), (uid, gid));
        }
    }
}

/// Only a privileged process can give a file to another user.
fn can_give_files_away(directory: &Path) -> bool {
    let probe = directory.join("probe");
    fs::write(&probe, b"").unwrap();
    let given = std::os::unix::fs::chown(&probe, Some(DAEMON.0), Some(DAEMON.1)).is_ok();
    fs::remove_file(probe).unwrap();
    given
}

#[test]
fn root_deep_check_recreates_a_missing_volume_lock_for_the_daemon() {
    let dir = tempfile::tempdir().unwrap();
    if !can_give_files_away(dir.path()) {
        eprintln!(
            "root_deep_check_recreates_a_missing_volume_lock_for_the_daemon: skipped: running \
             maki-check as another user needs root"
        );
        return;
    }
    let root = dir.path().join("vol");
    let backing = Arc::new(FileBacking::new(&root).unwrap());
    let geometry = Geometry::compute(512, 512, 512, 544, 1 << 20, 64 << 10).unwrap();
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x0e5),
            provider_type: "local-aes-gcm-siv".into(),
            crypto_compatibility_id: "local-aes-gcm-siv-v1".into(),
            key_identity: "k".into(),
            geometry,
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    {
        let mut volume = Volume::recover(
            backing.clone() as Arc<dyn Backing>,
            VolumeOptions {
                journal_segment_size: 4096,
            },
        )
        .unwrap();
        volume.write_ct(3, &vec![0x11; 540], true).unwrap();
        volume.checkpoint().unwrap();
    }
    drop(backing);
    // The daemon user's volume, after a restore that dropped the lock file.
    give(dir.path(), DAEMON);
    fs::remove_file(root.join("volume.lock")).unwrap();
    let root = root.to_str().unwrap();

    succeeded("root deep check", &run(&[root, "--deep"], None));
    let lock = fs::metadata(Path::new(root).join("volume.lock")).unwrap();
    assert_eq!(
        (lock.uid(), lock.gid(), lock.mode() & 0o777),
        (DAEMON.0, DAEMON.1, 0o600)
    );
    succeeded(
        "daemon-user deep check after root's",
        &run(&[root, "--deep"], Some(DAEMON)),
    );
}
