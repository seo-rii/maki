//! A check through a read-only view of the backing.
//!
//! `maki check`, `maki-check` and `maki volume inspect` failed on a backing
//! they cannot write (a read-only mount, a tree whose directories this user
//! may not write) with "Read-only file system" or "Permission denied": they
//! opened every file read-write, and the deep check took the volume lock
//! exclusively, creating the lock file when it was missing. They now read
//! such a backing through `FileBacking::read_only`, and a check through that
//! view must change nothing: it writes, syncs, creates and removes nothing,
//! and takes the volume lock shared through a read-only descriptor, which
//! still excludes a writer, without ever creating the lock file.
//!
//! It must also claim no more than reading proves. What it reads may exist
//! only in the page cache (a failed writeback, or a process that stopped
//! before its sync, leaves such bytes; K-01), and recovery rewrites and
//! syncs everything it accepts, and repairs what it must, before a writer
//! resumes: nothing of that can happen through the view. So the deep
//! verdict through it is `unproven`, never `clean`, and what recovery would
//! change (records to replay, a torn tail to truncate) is a warning, where a
//! writable check reports it as information about ordinary replay.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::SystemTime;

use uuid::Uuid;

use maki_backing::{Backing, FileBacking};
use maki_core::check::deep_check;
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::checker::{check_volume, CheckReport};
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};

const CT_LEN: usize = 540;
const SEGMENT: u64 = 4096;

fn superblock() -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(0x0EAD_0471),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "k".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 1024, 512 * 64).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn ct(stamp: u8) -> Vec<u8> {
    vec![stamp; CT_LEN]
}

/// A new volume in `root`, attached (its writer holds the volume lock).
fn attach(root: &Path) -> Volume {
    let backing: Arc<dyn Backing> = Arc::new(FileBacking::new(root).unwrap());
    if !backing.exists(layout::SUPERBLOCK_A).unwrap() {
        init::create_volume(backing.as_ref(), superblock()).unwrap();
    }
    Volume::recover(
        backing,
        VolumeOptions {
            journal_segment_size: SEGMENT,
        },
    )
    .unwrap()
}

fn read_only(root: &Path) -> Arc<dyn Backing> {
    Arc::new(FileBacking::read_only(root).unwrap())
}

fn writable(root: &Path) -> Arc<dyn Backing> {
    Arc::new(FileBacking::new(root).unwrap())
}

/// Every entry below `root`: its path, its length, its bytes if it is a
/// file, and its modification time, which a rewrite of identical bytes, a
/// truncation, and a created or removed entry (in its directory) change.
/// The lock file's bytes (it holds none) are not read: Windows refuses a
/// read of a file another handle holds locked, as an attached writer does.
fn tree(root: &Path) -> Vec<(PathBuf, u64, Option<Vec<u8>>, SystemTime)> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            None
        } else if path.ends_with(layout::VOLUME_LOCK) {
            None
        } else {
            Some(std::fs::read(&path).unwrap())
        };
        entries.push((path, metadata.len(), bytes, metadata.modified().unwrap()));
    }
    entries.sort();
    entries
}

fn lines(report: &CheckReport) -> String {
    let mut text = String::new();
    for (kind, lines) in [
        ("info", &report.info),
        ("warning", &report.warnings),
        ("ERROR", &report.errors),
    ] {
        for line in lines {
            text += &format!("{kind}: {line}\n");
        }
    }
    text
}

fn verdict(report: &CheckReport) -> Option<&str> {
    report
        .info
        .iter()
        .find_map(|line| line.strip_prefix("deep check verdict: "))
}

fn read_only_notice(report: &CheckReport) -> bool {
    report.warnings.iter().any(|line| {
        line.starts_with("read-only check: ")
            && line.contains("page cache")
            && line.contains("nothing was written, synced or repaired")
    })
}

#[test]
fn a_deep_check_through_a_read_only_view_changes_nothing_and_is_never_clean() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let mut volume = attach(&root);
    for unit in 0..6u8 {
        volume.write_ct(u64::from(unit), &ct(unit), false).unwrap();
    }
    volume.flush().unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    let before = tree(&root);

    let report = deep_check(read_only(&root), SEGMENT).unwrap();
    assert_eq!(
        tree(&root),
        before,
        "the read-only check changed the backing"
    );
    assert!(report.ok(), "{}", lines(&report));
    // It read what a writable check reads.
    assert!(
        report
            .info
            .iter()
            .any(|line| line.contains("slots: 6 allocated, 0 invalid")),
        "{}",
        lines(&report)
    );
    assert_eq!(verdict(&report), Some("unproven"), "{}", lines(&report));
    assert!(read_only_notice(&report), "{}", lines(&report));

    // The same volume through a writable backing: only the access differs.
    let report = deep_check(writable(&root), SEGMENT).unwrap();
    assert_eq!(verdict(&report), Some("clean"), "{}", lines(&report));
    assert!(!read_only_notice(&report), "{}", lines(&report));
}

#[test]
fn a_read_only_deep_check_reports_what_recovery_would_change_as_warnings() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let mut volume = attach(&root);
    volume.write_ct(0, &ct(1), true).unwrap(); // durable, not checkpointed
    volume.write_ct(1, &ct(2), false).unwrap(); // volatile: torn below
    let segment = volume.journal_active_segment_path().unwrap();
    drop(volume);
    // What a crash leaves of the unsynced append: part of its record.
    let path = root.join(&segment);
    let len = std::fs::metadata(&path).unwrap().len();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(len - 200)
        .unwrap();
    let before = tree(&root);

    let report = deep_check(read_only(&root), SEGMENT).unwrap();
    assert_eq!(
        tree(&root),
        before,
        "the read-only check changed the backing"
    );
    assert!(report.ok(), "{}", lines(&report));
    assert_eq!(verdict(&report), Some("unproven"), "{}", lines(&report));
    for pending in ["1 record(s) newer than the checkpoint", "torn tail"] {
        assert!(
            report.warnings.iter().any(|line| line.contains(pending)),
            "{pending}: {}",
            lines(&report)
        );
    }

    // A writable check reports the same journal as ordinary replay.
    let report = deep_check(writable(&root), SEGMENT).unwrap();
    assert_eq!(verdict(&report), Some("clean"), "{}", lines(&report));
    assert!(
        !report
            .warnings
            .iter()
            .any(|line| line.contains("torn tail") || line.contains("newer than")),
        "{}",
        lines(&report)
    );
    assert!(
        report.info.iter().any(|line| line.contains("torn tail")),
        "{}",
        lines(&report)
    );
}

#[test]
fn a_read_only_deep_check_refuses_a_volume_a_writer_holds() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let volume = attach(&root);
    let before = tree(&root);
    let report = deep_check(read_only(&root), SEGMENT).unwrap();
    assert!(
        report
            .errors
            .iter()
            .any(|line| line.contains("lock is held")),
        "{}",
        lines(&report)
    );
    assert_eq!(verdict(&report), None, "{}", lines(&report));
    assert_eq!(tree(&root), before);
    drop(volume);
    let report = deep_check(read_only(&root), SEGMENT).unwrap();
    assert!(report.ok(), "{}", lines(&report));
}

/// The read-only view of a root that, when the deep check reads the key
/// canary (after its lock, before the journal and the slots), asks whether a
/// writer could take the volume lock now.
struct WriterProbe {
    view: FileBacking,
    root: PathBuf,
    writer: std::sync::Mutex<Option<std::io::ErrorKind>>,
}

impl Backing for WriterProbe {
    fn open(
        &self,
        path: &str,
        create: bool,
    ) -> std::io::Result<Arc<dyn maki_backing::BackingFile>> {
        if path == layout::KEY_CANARY_A {
            let attempt = FileBacking::new(&self.root)
                .unwrap()
                .try_lock(layout::VOLUME_LOCK)
                .map(drop);
            *self.writer.lock().unwrap() = Some(match attempt {
                Ok(()) => std::io::ErrorKind::Other,
                Err(error) => error.kind(),
            });
        }
        self.view.open(path, create)
    }
    fn exists(&self, path: &str) -> std::io::Result<bool> {
        self.view.exists(path)
    }
    fn remove(&self, path: &str) -> std::io::Result<()> {
        self.view.remove(path)
    }
    fn rename(&self, from: &str, to: &str) -> std::io::Result<()> {
        self.view.rename(from, to)
    }
    fn create_dir_all(&self, path: &str) -> std::io::Result<()> {
        self.view.create_dir_all(path)
    }
    fn list(&self, dir: &str) -> std::io::Result<Vec<String>> {
        self.view.list(dir)
    }
    fn list_skipping_non_utf8(&self, dir: &str) -> std::io::Result<Vec<String>> {
        self.view.list_skipping_non_utf8(dir)
    }
    fn sync_dir(&self, dir: &str) -> std::io::Result<()> {
        self.view.sync_dir(dir)
    }
    fn try_lock(&self, path: &str) -> std::io::Result<Box<dyn maki_backing::VolumeLock>> {
        self.view.try_lock(path)
    }
    fn is_read_only(&self) -> bool {
        self.view.is_read_only()
    }
    fn try_lock_shared_existing(
        &self,
        path: &str,
    ) -> std::io::Result<Box<dyn maki_backing::VolumeLock>> {
        self.view.try_lock_shared_existing(path)
    }
}

/// The shared lock excludes a writer for the whole check, and only then is
/// released: a daemon that starts meanwhile is refused, as it is by a
/// writable deep check's exclusive lock.
#[test]
fn a_read_only_deep_check_excludes_a_writer_while_it_reads() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let mut volume = attach(&root);
    volume.write_ct(2, &ct(2), true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);

    let probe = Arc::new(WriterProbe {
        view: FileBacking::read_only(&root).unwrap(),
        root: root.clone(),
        writer: std::sync::Mutex::new(None),
    });
    let report = deep_check(probe.clone() as Arc<dyn Backing>, SEGMENT).unwrap();
    assert!(report.ok(), "{}", lines(&report));
    assert_eq!(verdict(&report), Some("unproven"), "{}", lines(&report));
    assert_eq!(
        *probe.writer.lock().unwrap(),
        Some(std::io::ErrorKind::WouldBlock),
        "a writer could take the volume lock during the check"
    );
    // Released with the check.
    drop(attach(&root));
}

#[test]
fn a_read_only_deep_check_never_creates_the_lock_file_and_does_not_run_without_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    drop(attach(&root));
    // A copy or restore that dropped the empty lock file.
    std::fs::remove_file(root.join(layout::VOLUME_LOCK)).unwrap();
    let before = tree(&root);

    let report = deep_check(read_only(&root), SEGMENT).unwrap();
    assert!(!root.join(layout::VOLUME_LOCK).exists());
    assert_eq!(
        tree(&root),
        before,
        "the read-only check changed the backing"
    );
    assert!(!report.ok(), "{}", lines(&report));
    assert!(
        report.errors.iter().any(|line| line.contains(&format!(
            "volume lock: {} is missing, and a read-only check cannot create it",
            layout::VOLUME_LOCK
        ))),
        "{}",
        lines(&report)
    );
    // Nothing after the lock ran, so nothing claims a verdict.
    assert_eq!(verdict(&report), None, "{}", lines(&report));
}

#[test]
fn the_fast_check_through_a_read_only_view_says_what_it_cannot_prove() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("volume");
    let mut volume = attach(&root);
    volume.write_ct(3, &ct(3), true).unwrap();
    volume.checkpoint().unwrap();
    drop(volume);
    let before = tree(&root);

    let report = check_volume(read_only(&root).as_ref()).unwrap();
    assert_eq!(tree(&root), before);
    assert!(report.ok(), "{}", lines(&report));
    assert!(read_only_notice(&report), "{}", lines(&report));
    let report = check_volume(writable(&root).as_ref()).unwrap();
    assert!(!read_only_notice(&report), "{}", lines(&report));
}
