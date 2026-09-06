//! BUG-014: binding a control socket must not alter unrelated filesystem
//! creation in another thread. This binary has one test because its initial
//! umask is process-wide; production code must never change that umask.

#![cfg(unix)]

use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::Barrier;

use maki_control::uds::bind_control_socket;

#[test]
fn bind_preserves_concurrent_directory_permissions() {
    // SAFETY: this isolated test binary establishes its filesystem policy
    // before starting either worker. The worker code must leave it alone.
    let original_umask = unsafe { libc::umask(0o022) };
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("control.sock");
    let directory = root.path().join("concurrent-directory");
    let start = Barrier::new(2);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .build()
        .unwrap();

    let (created, wrong_mode) = std::thread::scope(|scope| {
        let binder = scope.spawn(|| {
            let _entered = runtime.enter();
            start.wait();
            for _ in 0..4_000 {
                drop(bind_control_socket(&socket, None).unwrap());
            }
        });
        start.wait();
        let mut created = 0;
        let mut wrong_mode = None;
        while !binder.is_finished() {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let mode = std::fs::metadata(&directory).unwrap().permissions().mode() & 0o777;
            if mode != 0o700 {
                wrong_mode.get_or_insert(mode);
                // Restore traversal for fixture cleanup after recording the
                // observed permissions; the test also works when run as root.
                std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700))
                    .unwrap();
            }
            std::fs::remove_dir(&directory).unwrap();
            created += 1;
        }
        binder.join().unwrap();
        (created, wrong_mode)
    });
    // SAFETY: both workers have stopped; restore only the test setup change.
    unsafe { libc::umask(original_umask) };

    assert!(created > 0, "directory creation must overlap socket binds");
    assert_eq!(
        wrong_mode, None,
        "binding a socket changed a concurrent private directory's mode"
    );
}
