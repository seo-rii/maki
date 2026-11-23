use std::io::{Read, Write};
use std::os::fd::FromRawFd;

use super::*;

/// A child forked from this process that waits before its `exec` until it is
/// dropped. Until then it holds a copy of every descriptor this process had
/// when it forked, as any child of `Command::spawn` does between its fork and
/// its `exec`.
struct PausedChild {
    resume: std::io::PipeWriter,
    spawner: Option<std::thread::JoinHandle<io::Result<std::process::ExitStatus>>>,
}

impl PausedChild {
    fn fork() -> Self {
        use std::os::unix::process::CommandExt;
        let (mut forked, forked_writer) = std::io::pipe().unwrap();
        let (resume_reader, resume) = std::io::pipe().unwrap();
        let parent_end = resume.as_raw_fd();
        let mut command = std::process::Command::new("/bin/true");
        // SAFETY: the hook runs in the forked child before `exec` and only
        // closes, writes and reads pipe descriptors; it allocates nothing.
        unsafe {
            command.pre_exec(move || {
                // Without the parent's write end, a parent that dies without
                // resuming the child ends its wait instead of hanging it.
                drop(std::os::fd::OwnedFd::from_raw_fd(parent_end));
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

/// The socket directory lock is a `flock`, which belongs to the open file
/// description. A child forked meanwhile shares that description until its
/// `exec`; when releasing only closed the descriptor, the next bind or
/// listener drop in the directory waited for that child.
#[test]
fn a_released_socket_directory_lock_is_free_while_a_forked_child_holds_its_descriptor() {
    let dir = tempfile::tempdir().unwrap();
    let lock = lock_socket_directory(&dir.path().join("control.sock")).unwrap();
    let child = PausedChild::fork();
    drop(lock);
    // The directory lock blocks; probe without waiting for the child.
    let probe = std::fs::File::open(dir.path()).unwrap();
    assert!(
        probe.try_lock().is_ok(),
        "a released socket directory lock stayed held for a forked child"
    );
    drop((probe, child));
}
