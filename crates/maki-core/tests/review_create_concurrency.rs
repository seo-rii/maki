//! BUG-039: volume creation holds the same exclusion lock as attach, before
//! its first empty-root check through its final directory synchronization.

#![cfg(unix)]

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::Duration;

use maki_backing::{Backing, BackingFile, FileBacking, VolumeLock};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::error::FormatError;
use maki_format::geometry::Geometry;
use maki_format::superblock::Superblock;
use maki_format::{init, layout};
use uuid::Uuid;

#[derive(Clone, Copy)]
enum PausePoint {
    FirstCheck,
    FinalSync,
}

struct PausedCreate {
    inner: Arc<FileBacking>,
    point: PausePoint,
    paused_once: AtomicBool,
    paused: mpsc::SyncSender<()>,
    resume: Mutex<mpsc::Receiver<()>>,
}

impl PausedCreate {
    fn pause(&self) {
        if !self.paused_once.swap(true, Ordering::SeqCst) {
            self.paused.send(()).unwrap();
            self.resume.lock().unwrap().recv().unwrap();
        }
    }
}

impl Backing for PausedCreate {
    fn open(&self, path: &str, create: bool) -> io::Result<Arc<dyn BackingFile>> {
        self.inner.open(path, create)
    }

    fn exists(&self, path: &str) -> io::Result<bool> {
        if matches!(self.point, PausePoint::FirstCheck) && path == layout::SUPERBLOCK_A {
            self.pause();
        }
        self.inner.exists(path)
    }

    fn remove(&self, path: &str) -> io::Result<()> {
        self.inner.remove(path)
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        self.inner.rename(from, to)
    }

    fn create_dir_all(&self, path: &str) -> io::Result<()> {
        self.inner.create_dir_all(path)
    }

    fn list(&self, path: &str) -> io::Result<Vec<String>> {
        self.inner.list(path)
    }

    fn sync_dir(&self, path: &str) -> io::Result<()> {
        // The durable mark is created only after every A/B metadata store.
        // Its presence identifies the final root sync without mocking I/O.
        if matches!(self.point, PausePoint::FinalSync)
            && path.is_empty()
            && self.inner.exists(layout::JOURNAL_DURABLE_MARK)?
        {
            self.pause();
        }
        self.inner.sync_dir(path)
    }

    fn try_lock(&self, path: &str) -> io::Result<Box<dyn VolumeLock>> {
        self.inner.try_lock(path)
    }

    fn free_bytes(&self) -> io::Result<Option<u64>> {
        self.inner.free_bytes()
    }
}

fn superblock(identity: u128) -> Superblock {
    Superblock {
        generation: 0,
        volume_uuid: Uuid::from_u128(identity),
        provider_type: "fake".into(),
        crypto_compatibility_id: "test-profile-v1".into(),
        key_identity: "fixture".into(),
        geometry: Geometry::compute(512, 512, 512, 544, 512 * 64, 512 * 16).unwrap(),
        format_version: 1,
        created_unix: 0,
    }
}

fn create(backing: &dyn Backing, identity: u128, discard: bool) -> Result<Superblock, FormatError> {
    if discard {
        init::create_volume_with_discard(backing, superblock(identity))
    } else {
        init::create_volume(backing, superblock(identity))
    }
}

fn assert_initializer_excludes_create_and_attach(point: PausePoint) {
    for discard in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let actual = Arc::new(FileBacking::new(root.path()).unwrap());
        let (paused_tx, paused_rx) = mpsc::sync_channel(0);
        let (resume_tx, resume_rx) = mpsc::sync_channel(0);
        let delayed = PausedCreate {
            inner: actual.clone(),
            point,
            paused_once: AtomicBool::new(false),
            paused: paused_tx,
            resume: Mutex::new(resume_rx),
        };
        let creator = thread::spawn(move || create(&delayed, 0xBBBB, discard));
        paused_rx.recv_timeout(Duration::from_secs(10)).unwrap();

        // Store the observations and unblock/join the creator before any
        // assertion can fail, so RED does not leak a parked test thread.
        let competitor = create(actual.as_ref(), 0xAAAA, !discard);
        let options = VolumeOptions {
            journal_segment_size: 4096,
        };
        let attach = Volume::recover(actual.clone(), options.clone());
        resume_tx.send(()).unwrap();
        let created = creator.join().unwrap();
        assert!(matches!(competitor, Err(FormatError::Io(error))
            if error.kind() == io::ErrorKind::WouldBlock));
        assert!(
            matches!(attach, Err(ref error) if error.to_string().contains("VOLUME_ALREADY_ATTACHED")),
            "attach must observe the initializer's volume lock"
        );
        created.unwrap();

        assert!(matches!(
            create(actual.as_ref(), 0xAAAA, discard),
            Err(FormatError::AlreadyExists(_))
        ));
        let mut volume = Volume::recover(actual.clone(), options.clone()).unwrap();
        assert_eq!(volume.superblock().volume_uuid, Uuid::from_u128(0xBBBB));
        let ciphertext = vec![0x51; 540];
        volume.write_ct(0, &ciphertext, true).unwrap();
        assert!(matches!(create(actual.as_ref(), 0xAAAA, discard),
            Err(FormatError::Io(error)) if error.kind() == io::ErrorKind::WouldBlock));
        drop(volume);
        let recovered = Volume::recover(actual, options).unwrap();
        assert_eq!(recovered.superblock().volume_uuid, Uuid::from_u128(0xBBBB));
        assert_eq!(recovered.read_ct(0).unwrap().unwrap().1, ciphertext);
    }
}

#[test]
fn create_excludes_competing_create_and_attach_before_first_check() {
    assert_initializer_excludes_create_and_attach(PausePoint::FirstCheck);
}

#[test]
fn create_keeps_exclusion_through_final_directory_sync() {
    assert_initializer_excludes_create_and_attach(PausePoint::FinalSync);
}
