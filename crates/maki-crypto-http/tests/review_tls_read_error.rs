//! BUG-188: an interrupted combined mTLS PEM read must erase its owner.
//! Linux only. The `read` interposer affects this executable alone, and only
//! the private temporary inode selected by the current test thread.
#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::os::unix::fs::{MetadataExt, PermissionsExt};

use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;

const FILE_LEN: usize = 8192;
const PARTIAL: usize = 1024;
const MARKER_LEN: usize = 64;

#[derive(Clone, Copy)]
struct Watch {
    enabled: bool,
    inject: bool,
    dev: u64,
    ino: u64,
    marker: [u8; MARKER_LEN],
    selected_allocation: usize,
    reader_allocation: usize,
    initialized_reader: bool,
    reads: usize,
    bytes_read: usize,
    injected_errors: usize,
    deallocations: usize,
    zeroed: usize,
    retained_marker: usize,
}

const EMPTY: Watch = Watch {
    enabled: false,
    inject: false,
    dev: 0,
    ino: 0,
    marker: [0; MARKER_LEN],
    selected_allocation: 0,
    reader_allocation: 0,
    initialized_reader: false,
    reads: 0,
    bytes_read: 0,
    injected_errors: 0,
    deallocations: 0,
    zeroed: 0,
    retained_marker: 0,
};

thread_local! {
    static WATCH: Cell<Watch> = const { Cell::new(EMPTY) };
}

struct ObserveReaderAllocation;

// SAFETY: allocation and deallocation delegate to System. Only allocations of
// the known reader capacity are zero-initialized for observation. The syscall
// hook identifies the exact allocation receiving the private file's first
// read. Only that still-live, fully initialized allocation is inspected before
// System.dealloc; neither freed nor uninitialized memory is read.
unsafe impl GlobalAlloc for ObserveReaderAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let selected = WATCH
            .try_with(|state| state.get().enabled && layout.size() == FILE_LEN)
            .unwrap_or(false);
        let pointer = if selected {
            unsafe { System.alloc_zeroed(layout) }
        } else {
            unsafe { System.alloc(layout) }
        };
        if selected && !pointer.is_null() {
            let _ = WATCH.try_with(|state| {
                let mut watch = state.get();
                watch.selected_allocation = pointer as usize;
                state.set(watch);
            });
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if layout.size() == FILE_LEN && !pointer.is_null() {
            let _ = WATCH.try_with(|state| {
                let mut watch = state.get();
                if watch.enabled {
                    watch.selected_allocation = pointer as usize;
                    state.set(watch);
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = WATCH.try_with(|state| {
            let mut watch = state.get();
            if watch.enabled
                && watch.initialized_reader
                && watch.reader_allocation == pointer as usize
                && layout.size() == FILE_LEN
            {
                let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                watch.deallocations += 1;
                watch.zeroed += usize::from(bytes.iter().all(|byte| *byte == 0));
                watch.retained_marker +=
                    usize::from(bytes.windows(MARKER_LEN).any(|part| part == watch.marker));
                watch.reader_allocation = 0;
                state.set(watch);
            }
        });
        unsafe { System.dealloc(pointer, layout) };
    }
}

#[global_allocator]
static ALLOCATOR: ObserveReaderAllocation = ObserveReaderAllocation;

// SAFETY: this preserves libc read's signature and buffer contract. Every
// ordinary read delegates directly to SYS_read. Only this test thread's exact
// temporary device/inode gets one short read followed by a synthetic EIO.
// No environment variable, preload library, filesystem corruption, or other
// process is involved.
/// # Safety
/// `buffer` must be writable for `count` bytes, as required by libc `read`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn read(
    fd: libc::c_int,
    buffer: *mut libc::c_void,
    count: libc::size_t,
) -> libc::ssize_t {
    let state = WATCH.try_with(Cell::get).unwrap_or(EMPTY);
    if state.enabled && count > 0 {
        let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
        if unsafe { libc::syscall(libc::SYS_fstat, fd, metadata.as_mut_ptr()) } == 0 {
            let metadata = unsafe { metadata.assume_init() };
            if metadata.st_dev == state.dev && metadata.st_ino == state.ino {
                if state.inject && state.reads > 0 {
                    let _ = WATCH.try_with(|cell| {
                        let mut watch = cell.get();
                        watch.reads += 1;
                        watch.injected_errors += 1;
                        cell.set(watch);
                    });
                    unsafe { *libc::__errno_location() = libc::EIO };
                    return -1;
                }
                let requested = if state.inject {
                    count.min(PARTIAL)
                } else {
                    count
                };
                let result = unsafe { libc::syscall(libc::SYS_read, fd, buffer, requested) }
                    as libc::ssize_t;
                let _ = WATCH.try_with(|cell| {
                    let mut watch = cell.get();
                    if watch.reads == 0 {
                        watch.reader_allocation = buffer as usize;
                        watch.initialized_reader = watch.selected_allocation == buffer as usize;
                    }
                    watch.reads += 1;
                    watch.bytes_read += result.max(0) as usize;
                    cell.set(watch);
                });
                return result;
            }
        }
    }
    unsafe { libc::syscall(libc::SYS_read, fd, buffer, count) as libc::ssize_t }
}

#[derive(Debug)]
struct Observation {
    accepted: bool,
    read_error: bool,
    permission_error: bool,
    initialized_reader: bool,
    reads: usize,
    bytes_read: usize,
    injected_errors: usize,
    deallocations: usize,
    zeroed: usize,
    retained_marker: usize,
}

fn observe(inject: bool, mode: u32) -> Observation {
    static TLS_PROVIDER: std::sync::Once = std::sync::Once::new();
    TLS_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
    // Generate an expendable test identity. No actual credential is read or
    // emitted; the observer reports counts, never the marker/key bytes.
    let identity = rcgen::generate_simple_self_signed(vec!["maki-audit.invalid".into()]).unwrap();
    let key_pem = identity.key_pair.serialize_pem();
    let marker: [u8; MARKER_LEN] = key_pem.lines().nth(1).unwrap().as_bytes()[..MARKER_LEN]
        .try_into()
        .unwrap();
    let mut contents = format!("{}{}", key_pem, identity.cert.pem()).into_bytes();
    assert!(contents.len() < PARTIAL);
    contents.resize(FILE_LEN, b'\n');
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("synthetic-combined.pem");
    std::fs::write(&path, &contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
    let metadata = std::fs::metadata(&path).unwrap();
    let config = maki_format::config::parse_config(&format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-tls-read"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit-tls-read-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[[crypto.http.endpoint]]
name = "primary"
url = "https://localhost"
[crypto.http.encrypt]
method = "POST"
path = "/encrypt"
[crypto.http.decrypt]
method = "POST"
path = "/decrypt"
[crypto.http.tls]
client_cert_file = {:?}
[backing]
root = "/tmp/unused-audit-tls-read"
"#,
        path.to_str().unwrap(),
    ))
    .unwrap();
    let keys = MapKeySource::new();
    WATCH.with(|cell| {
        assert!(!cell.get().enabled);
        cell.set(Watch {
            enabled: true,
            inject,
            dev: metadata.dev(),
            ino: metadata.ino(),
            marker,
            ..EMPTY
        });
    });
    let result = HttpCryptoProvider::from_config(&config, "https://localhost", &keys);
    let accepted = result.is_ok();
    let read_error = result
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("os error 5"));
    let permission_error = result
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("mode 0644"));
    drop(result);
    let watch = WATCH.with(|cell| cell.replace(EMPTY));
    Observation {
        accepted,
        read_error,
        permission_error,
        initialized_reader: watch.initialized_reader,
        reads: watch.reads,
        bytes_read: watch.bytes_read,
        injected_errors: watch.injected_errors,
        deallocations: watch.deallocations,
        zeroed: watch.zeroed,
        retained_marker: watch.retained_marker,
    }
}

fn assert_reader_wiped(observation: &Observation) {
    assert!(observation.initialized_reader, "{observation:?}");
    assert_eq!(observation.deallocations, 1, "{observation:?}");
    assert_eq!(
        observation.retained_marker, 0,
        "private-key marker retained: {observation:?}"
    );
    assert_eq!(observation.zeroed, 1, "{observation:?}");
}

#[test]
fn partial_combined_identity_read_error_erases_key_bytes() {
    let observed = observe(true, 0o600);
    assert!(!observed.accepted && observed.read_error, "{observed:?}");
    assert_eq!(observed.injected_errors, 1, "{observed:?}");
    assert_eq!(observed.reads, 2, "{observed:?}");
    assert_eq!(observed.bytes_read, PARTIAL, "{observed:?}");
    assert_reader_wiped(&observed);
}

#[test]
fn successful_combined_identity_construction_erases_the_reader_owner() {
    let observed = observe(false, 0o600);
    assert!(observed.accepted, "{observed:?}");
    assert_eq!(observed.injected_errors, 0, "{observed:?}");
    assert_eq!(observed.bytes_read, FILE_LEN, "{observed:?}");
    assert_reader_wiped(&observed);
}

#[test]
fn ordinary_combined_identity_permission_rejection_erases_the_reader_owner() {
    let observed = observe(false, 0o644);
    assert!(
        !observed.accepted && observed.permission_error,
        "{observed:?}"
    );
    assert_eq!(observed.injected_errors, 0, "{observed:?}");
    assert_eq!(observed.bytes_read, FILE_LEN, "{observed:?}");
    assert_reader_wiped(&observed);
}
