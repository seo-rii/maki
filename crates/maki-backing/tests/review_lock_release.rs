//! A `flock` lock belongs to the open file description, and every child
//! forked by any thread holds a copy of the parent's descriptors, close-on-exec
//! ones included, until its `exec` closes them. Closing the holder's
//! descriptor therefore did not release a lock while such a child existed: the
//! next attach, store open or reopen in the same instant was refused as if
//! another process still held it. Each test forks a child that stops before its
//! `exec` while a lock is held, releases the lock through the product API, and
//! requires that the lock can be taken again while the child is still waiting.

#![cfg(target_os = "linux")]

#[path = "support/private_dir.rs"]
mod private_dir;

#[path = "support/other_filesystem.rs"]
mod other_filesystem;

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::process::CommandExt;
use std::process::{Command, ExitStatus};
use std::thread::JoinHandle;

use maki_backing::remote_witness::StateStore;
use maki_backing::{Backing, FileBacking, RollbackBacking};

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

#[test]
fn a_dropped_lock_is_free_while_a_forked_child_still_holds_its_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let backing = FileBacking::new(dir.path()).unwrap();
    let lock = backing.try_lock("volume.lock").unwrap();
    assert_eq!(
        backing.try_lock("volume.lock").err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    let child = PausedChild::fork();
    drop(lock);
    let again = backing.try_lock("volume.lock");
    assert!(
        again.is_ok(),
        "a released volume lock stayed held for a forked child: {:?}",
        again.err()
    );
    drop(child);
}

#[test]
fn a_closed_rollback_backing_reopens_while_a_forked_child_holds_its_descriptors() {
    let root = tempfile::tempdir().unwrap();
    let Some(witness) = other_filesystem::tempdir(root.path()) else {
        return;
    };
    let backing = RollbackBacking::create(root.path(), witness.path(), 16 * 4096).unwrap();
    let child = PausedChild::fork();
    drop(backing);
    let reopened = RollbackBacking::open(root.path(), witness.path());
    assert!(
        reopened.is_ok(),
        "the backing and witness locks stayed held for a forked child: {:?}",
        reopened.err()
    );
    drop(child);
}

#[test]
fn a_closed_remote_witness_store_reopens_while_a_forked_child_holds_its_descriptor() {
    let dir = private_dir::tempdir().unwrap();
    let store = StateStore::create(dir.path(), [1; 16]).unwrap();
    let child = PausedChild::fork();
    drop(store);
    let reopened = StateStore::open(dir.path());
    assert!(
        reopened.is_ok(),
        "the state directory lock stayed held for a forked child: {:?}",
        reopened.err()
    );
    drop(child);
}
