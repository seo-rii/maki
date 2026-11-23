//! `RollbackBacking::restore_remote` only reads its snapshot, but it opened
//! every snapshot file read-write and created the snapshot's operation lock
//! if needed, so a snapshot kept where nothing can change it (a read-only
//! mount, immutable files, a read-only export, or files the administrator
//! may not write) failed with EROFS, EPERM or EACCES before the authority
//! was asked anything. Restore now reads the snapshot through a read-only
//! view and shares its existing operation lock; the target keeps every
//! check.
//!
//! The mode-bit case runs everywhere (a root test thread gives up
//! CAP_DAC_OVERRIDE). The read-only mount needs root for a private mount
//! namespace and the immutable flag needs root and filesystem support;
//! without them those cases are skipped with the reason printed.
#![cfg(target_os = "linux")]

use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};

use maki_backing::remote_gc::OperationGuard;
use maki_backing::remote_witness::{Action, Descriptor, Record, Request, Role, Rpc, StateStore};
use maki_backing::{Backing, FileBacking, MemBacking, RollbackBacking};

struct Admin(Mutex<StateStore>);

impl Rpc for Admin {
    fn call(&self, request: &Request) -> io::Result<Record> {
        self.0.lock().unwrap().handle(Role::Admin, request)
    }
}

fn inspect(rpc: &dyn Rpc) -> Record {
    rpc.call(&Request {
        authorization: None,
        operation_id: *uuid::Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    })
    .unwrap()
}

fn write(backing: &RollbackBacking, data: &[u8]) {
    let file = backing.open("payload", true).unwrap();
    file.write_at(0, data).unwrap();
    file.sync_data().unwrap();
    backing.sync_dir("").unwrap();
}

fn read(backing: &RollbackBacking) -> Vec<u8> {
    let file = backing.open("payload", false).unwrap();
    let mut bytes = vec![0; file.len().unwrap() as usize];
    file.read_at(0, &mut bytes).unwrap();
    bytes
}

/// A volume whose snapshot holds `snapshot` and whose current data is newer.
struct Fixture {
    root: tempfile::TempDir,
    snapshot: tempfile::TempDir,
    source: Descriptor,
    rpc: Arc<Admin>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let rpc = Arc::new(Admin(Mutex::new(
            StateStore::create_backing(Arc::new(MemBacking::new()), [0x5A; 16]).unwrap(),
        )));
        let backing = RollbackBacking::create_remote(root.path(), rpc.clone(), 4096).unwrap();
        write(&backing, b"snapshot");
        let snapshot = tempfile::tempdir().unwrap();
        let source = backing.snapshot_remote(snapshot.path()).unwrap();
        write(&backing, b"latest!!");
        drop(backing);
        Self {
            root,
            snapshot,
            source,
            rpc,
        }
    }

    fn snapshot(&self) -> &Path {
        self.snapshot.path()
    }

    fn restore(&self) -> io::Result<RollbackBacking> {
        let expected = inspect(self.rpc.as_ref());
        RollbackBacking::restore_remote(
            self.root.path(),
            self.snapshot(),
            &self.source,
            self.rpc.clone(),
            &expected,
        )
    }

    /// Restore from the snapshot, which must stay exactly as it was, and
    /// check that the authority moved to the restored state.
    fn restore_unchanged(&self) {
        let before = inspect(self.rpc.as_ref());
        let unchanged = tree(self.snapshot());
        let restored = self.restore();
        assert_eq!(
            tree(self.snapshot()),
            unchanged,
            "restore changed its snapshot"
        );
        let restored = restored.expect("restore must only read its snapshot");
        assert_eq!(read(&restored), b"snapshot");
        drop(restored);
        let after = inspect(self.rpc.as_ref()).current.unwrap();
        let previous = before.current.unwrap();
        assert_eq!(after.epoch, previous.epoch + 1);
        assert_eq!(after.anchor.generation, previous.anchor.generation + 1);
    }
}

/// Every entry below `root` (and `root` itself) with its mode and, for a
/// file, its bytes.
fn tree(root: &Path) -> Vec<(PathBuf, u32, Option<Vec<u8>>)> {
    let mut entries = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(path) = pending.pop() {
        let metadata = std::fs::symlink_metadata(&path).unwrap();
        let bytes = if metadata.is_dir() {
            for entry in std::fs::read_dir(&path).unwrap() {
                pending.push(entry.unwrap().path());
            }
            None
        } else {
            Some(std::fs::read(&path).unwrap())
        };
        entries.push((path, metadata.permissions().mode(), bytes));
    }
    entries.sort();
    entries
}

fn set_modes(root: &Path, file: u32, directory: u32) {
    for (path, mode, _) in tree(root) {
        let mode = if mode & 0o040000 != 0 {
            directory
        } else {
            file
        };
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }
}

/// Linux capability sets (`capget(2)`), version 3: two 32-bit words.
#[repr(C)]
struct CapabilityHeader {
    version: u32,
    pid: libc::c_int,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct CapabilityData {
    effective: u32,
    permitted: u32,
    inheritable: u32,
}

const CAP_DAC_OVERRIDE: u32 = 1;

fn capabilities(set: Option<&[CapabilityData; 2]>) -> io::Result<[CapabilityData; 2]> {
    // pid 0 names the calling thread.
    let mut header = CapabilityHeader {
        version: 0x2008_0522,
        pid: 0,
    };
    let mut data = set.copied().unwrap_or_default();
    let call = if set.is_some() {
        libc::SYS_capset
    } else {
        libc::SYS_capget
    };
    // SAFETY: both pointers reference live, correctly laid out structures
    // for the duration of the call; capget writes two data words.
    if unsafe { libc::syscall(call, &mut header, data.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(data)
}

/// Clears CAP_DAC_OVERRIDE from the calling thread's effective set until
/// the guard drops. Credentials are per thread (libtest runs each test on
/// its own thread); an unprivileged user has nothing to clear.
struct WithoutDacOverride([CapabilityData; 2]);

impl WithoutDacOverride {
    fn new() -> io::Result<Self> {
        let saved = capabilities(None)?;
        let mut reduced = saved;
        reduced[0].effective &= !(1 << CAP_DAC_OVERRIDE);
        capabilities(Some(&reduced))?;
        Ok(Self(saved))
    }
}

impl Drop for WithoutDacOverride {
    fn drop(&mut self) {
        let _ = capabilities(Some(&self.0));
    }
}

/// Gives the snapshot tree back its owner's write permission on drop, so
/// the temporary directories can be removed.
struct Writable<'a>(&'a Path);

impl Drop for Writable<'_> {
    fn drop(&mut self) {
        set_modes(self.0, 0o600, 0o700);
    }
}

fn refuses_writes(path: &Path) -> bool {
    std::fs::OpenOptions::new()
        .write(true)
        .open(path.join("rollback.format"))
        .is_err()
}

#[test]
fn restore_reads_a_snapshot_it_may_not_write() {
    let fixture = Fixture::new();
    let _writable = Writable(fixture.snapshot());
    set_modes(fixture.snapshot(), 0o400, 0o500);
    // Root ignores mode bits through CAP_DAC_OVERRIDE: give it up here.
    let _unprivileged = match WithoutDacOverride::new() {
        Ok(guard) => guard,
        Err(error) => {
            eprintln!("skipping: cannot drop CAP_DAC_OVERRIDE ({error})");
            return;
        }
    };
    assert!(
        refuses_writes(fixture.snapshot()),
        "the snapshot must refuse writes for this test to mean anything"
    );
    fixture.restore_unchanged();
}

/// Restore shares the snapshot's operation lock instead of taking it
/// exclusively. An operation that holds it exclusively (a snapshot into
/// that directory, GC or a writer of that root) still excludes the
/// restore, which refuses before asking the authority anything.
#[test]
fn restore_refuses_a_snapshot_another_operation_holds() {
    let fixture = Fixture::new();
    let disk = FileBacking::new(fixture.snapshot()).unwrap();
    let guard = OperationGuard::acquire(&disk).unwrap();
    let before = inspect(fixture.rpc.as_ref());
    let outcome = fixture.restore();
    assert_eq!(
        outcome.err().map(|error| error.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    assert_eq!(inspect(fixture.rpc.as_ref()), before);
    drop(guard);
    fixture.restore_unchanged();
}

const MOUNT_CHILD: &str = "MAKI_REVIEW_RESTORE_READ_ONLY_MOUNT";
const MOUNT_TEST: &str = "restore_reads_a_snapshot_on_a_read_only_mount";

fn c_path(path: &Path) -> std::ffi::CString {
    std::ffi::CString::new(path.as_os_str().as_bytes()).unwrap()
}

/// Detaches the read-only bind mount on drop, before the fixture's
/// directories are removed.
struct Mounted(std::ffi::CString);

impl Drop for Mounted {
    fn drop(&mut self) {
        // SAFETY: the path is a valid NUL-terminated string for the call.
        unsafe { libc::umount2(self.0.as_ptr(), libc::MNT_DETACH) };
    }
}

fn bind_read_only(path: &Path) -> Mounted {
    let target = c_path(path);
    // SAFETY: every pointer is null or a valid NUL-terminated string for
    // the call; this runs in a private mount namespace.
    unsafe {
        assert_eq!(
            libc::mount(
                target.as_ptr(),
                target.as_ptr(),
                std::ptr::null(),
                libc::MS_BIND,
                std::ptr::null(),
            ),
            0,
            "bind mount: {}",
            io::Error::last_os_error()
        );
        let mounted = Mounted(target);
        assert_eq!(
            libc::mount(
                std::ptr::null(),
                mounted.0.as_ptr(),
                std::ptr::null(),
                libc::MS_REMOUNT | libc::MS_BIND | libc::MS_RDONLY,
                std::ptr::null(),
            ),
            0,
            "read-only remount: {}",
            io::Error::last_os_error()
        );
        mounted
    }
}

#[test]
fn restore_reads_a_snapshot_on_a_read_only_mount() {
    if std::env::var_os(MOUNT_CHILD).is_some() {
        let fixture = Fixture::new();
        let _mounted = bind_read_only(fixture.snapshot());
        let error = std::fs::OpenOptions::new()
            .write(true)
            .open(fixture.snapshot().join("rollback.format"))
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::ReadOnlyFilesystem);
        fixture.restore_unchanged();
        return;
    }
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: a read-only bind mount in a private mount namespace needs root");
        return;
    }
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", MOUNT_TEST, "--nocapture", "--test-threads=1"])
        .env(MOUNT_CHILD, "1");
    // SAFETY: runs in the forked child before exec and only makes raw
    // system calls on static strings.
    unsafe {
        command.pre_exec(|| {
            if libc::unshare(libc::CLONE_NEWNS) != 0
                || libc::mount(
                    std::ptr::null(),
                    c"/".as_ptr(),
                    std::ptr::null(),
                    libc::MS_REC | libc::MS_PRIVATE,
                    std::ptr::null(),
                ) != 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let output = match command.output() {
        Ok(output) => output,
        Err(error) => {
            eprintln!("skipping: cannot enter a private mount namespace: {error}");
            return;
        }
    };
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "child failed:\n{text}");
    assert!(
        text.contains("test result: ok. 1 passed"),
        "the child did not run the scenario:\n{text}"
    );
}

const FS_IMMUTABLE_FL: libc::c_int = 0x10;

fn set_immutable(path: &Path, immutable: bool) -> io::Result<()> {
    let file = std::fs::File::open(path)?;
    let mut flags: libc::c_int = 0;
    use std::os::fd::AsRawFd;
    // SAFETY: the descriptor is open and both ioctls access one c_int.
    unsafe {
        if libc::ioctl(file.as_raw_fd(), libc::FS_IOC_GETFLAGS, &mut flags) != 0 {
            return Err(io::Error::last_os_error());
        }
        if immutable {
            flags |= FS_IMMUTABLE_FL;
        } else {
            flags &= !FS_IMMUTABLE_FL;
        }
        if libc::ioctl(file.as_raw_fd(), libc::FS_IOC_SETFLAGS, &flags) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Clears the immutable flag again on drop.
struct Immutable(Vec<PathBuf>);

impl Drop for Immutable {
    fn drop(&mut self) {
        for path in &self.0 {
            let _ = set_immutable(path, false);
        }
    }
}

/// An immutable copy refuses opening for writing and, on its directory,
/// even the write-access probe (EPERM, not EROFS or EACCES).
#[test]
fn restore_reads_an_immutable_snapshot() {
    // SAFETY: geteuid has no preconditions.
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("skipping: setting the immutable flag needs root");
        return;
    }
    let fixture = Fixture::new();
    let mut immutable = Immutable(Vec::new());
    for (path, _, _) in tree(fixture.snapshot()) {
        if let Err(error) = set_immutable(&path, true) {
            eprintln!("skipping: the filesystem refuses the immutable flag ({error})");
            return;
        }
        immutable.0.push(path);
    }
    assert!(
        refuses_writes(fixture.snapshot()),
        "the snapshot must refuse writes for this test to mean anything"
    );
    fixture.restore_unchanged();
}
