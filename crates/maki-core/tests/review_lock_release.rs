//! Detaching a volume released its lock only by closing the lock file's
//! descriptor. A `flock` lock belongs to the open file description, and a
//! child forked by any thread meanwhile (a test spawning a checker, a helper
//! running `mount`) shares it until its `exec`, so an immediate reattach in that
//! window failed with `AlreadyAttached` although no volume was attached.

#![cfg(target_os = "linux")]

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use std::sync::Arc;
use std::thread::JoinHandle;

use maki_backing::{Backing, FileBacking};
use maki_core::volume::{Volume, VolumeOptions};
use maki_format::geometry::Geometry;
use maki_format::init;
use maki_format::superblock::Superblock;

/// A child forked from this process that waits before its `exec` until it is
/// dropped. Until then it holds a copy of every descriptor this process had
/// when it forked, as any child of `Command::spawn` does between its fork and
/// its `exec`.
struct PausedChild {
    resume: io::PipeWriter,
    spawner: Option<JoinHandle<io::Result<ExitStatus>>>,
}

impl PausedChild {
    fn fork() -> Self {
        let (mut forked, forked_writer) = io::pipe().unwrap();
        let (resume_reader, resume) = io::pipe().unwrap();
        let parent_end = resume.as_raw_fd();
        let mut command = Command::new("/bin/true");
        // SAFETY: the hook runs in the forked child before `exec` and only
        // closes, writes and reads pipe descriptors; it allocates nothing.
        unsafe {
            command.pre_exec(move || {
                // Without the parent's write end, a parent that dies without
                // resuming the child ends its wait instead of hanging it.
                drop(OwnedFd::from_raw_fd(parent_end));
                (&forked_writer).write_all(&[1])?;
                (&resume_reader).read_exact(&mut [0])?;
                Ok(())
            });
        }
        // `spawn` returns only once the child has exec'd.
        let spawner = std::thread::spawn(move || command.spawn()?.wait());
        forked.read_exact(&mut [0]).expect("the child forked");
        Self {
            resume,
            spawner: Some(spawner),
        }
    }
}

impl Drop for PausedChild {
    fn drop(&mut self) {
        let _ = self.resume.write_all(&[1]);
        let status = self.spawner.take().unwrap().join();
        if !std::thread::panicking() {
            assert!(status.unwrap().unwrap().success());
        }
    }
}

fn options() -> VolumeOptions {
    VolumeOptions {
        journal_segment_size: 4096,
    }
}

#[test]
fn a_detached_volume_reattaches_while_a_forked_child_holds_the_lock_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let backing: Arc<dyn Backing> = Arc::new(FileBacking::new(dir.path()).unwrap());
    init::create_volume(
        backing.as_ref(),
        Superblock {
            generation: 0,
            volume_uuid: uuid::Uuid::from_u128(0x10C4),
            provider_type: "local-aes-gcm-siv".into(),
            crypto_compatibility_id: "local-aes-gcm-siv-v1".into(),
            key_identity: "k".into(),
            geometry: Geometry::compute(512, 512, 512, 544, 1 << 20, 64 << 10).unwrap(),
            format_version: 1,
            created_unix: 0,
        },
    )
    .unwrap();
    let mut volume = Volume::recover(backing.clone(), options()).unwrap();
    volume.write_ct(3, &[0x11; 540], true).unwrap();
    let child = PausedChild::fork();
    drop(volume);
    let reattached = Volume::recover(backing, options());
    assert!(
        reattached.is_ok(),
        "a detached volume stayed locked for a forked child: {:?}",
        reattached.err()
    );
    drop(child);
}
