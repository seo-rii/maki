//! Audit round 3 (nbdkit-adapter): drive the real `libmaki_nbdkit.so` C ABI
//! the way nbdkit does, without nbdkit (not installed on the audit host).
//!
//! The child process `dlopen`s the cdylib, reads the `nbdkit_plugin` struct
//! returned by `plugin_init` and calls config → config_complete → (open
//! before readiness) → after_fork → open/get_size/block_size → I/O with the
//! exact flag bits nbdkit passes → close/reopen → unload, reading `errno`
//! immediately after every failed callback as nbdkit's `get_error` does
//! (`errno_is_preserved = 1`).

#![cfg(target_os = "linux")]

#[path = "support/native_plugin.rs"]
mod native_plugin;

use std::ffi::{c_char, c_int, c_void, CString};
use std::process::Command;

const CHILD_ENV: &str = "MAKI_AUDIT3_NATIVE_SHIM_CHILD";

/// nbdkit-plugin.h (API v2) prefix up to `block_size`, as nbdkit reads it.
#[repr(C)]
struct Plugin {
    struct_size: u64,
    api_version: c_int,
    thread_model: c_int,
    name: *const c_char,
    longname: *const c_char,
    version: *const c_char,
    description: *const c_char,
    load: Option<unsafe extern "C" fn()>,
    unload: Option<unsafe extern "C" fn()>,
    config: Option<unsafe extern "C" fn(*const c_char, *const c_char) -> c_int>,
    config_complete: Option<unsafe extern "C" fn() -> c_int>,
    config_help: *const c_char,
    open: Option<unsafe extern "C" fn(c_int) -> *mut c_void>,
    close: Option<unsafe extern "C" fn(*mut c_void)>,
    get_size: Option<unsafe extern "C" fn(*mut c_void) -> i64>,
    can_write: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    can_flush: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    is_rotational: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    can_trim: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    _v1: [Option<unsafe extern "C" fn()>; 5],
    errno_is_preserved: c_int,
    dump_plugin: Option<unsafe extern "C" fn()>,
    can_zero: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    can_fua: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    pread: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64, u32) -> c_int>,
    pwrite: Option<unsafe extern "C" fn(*mut c_void, *const c_void, u32, u64, u32) -> c_int>,
    flush: Option<unsafe extern "C" fn(*mut c_void, u32) -> c_int>,
    trim: Option<unsafe extern "C" fn(*mut c_void, u32, u64, u32) -> c_int>,
    zero: Option<unsafe extern "C" fn(*mut c_void, u32, u64, u32) -> c_int>,
    magic_config_key: *const c_char,
    can_multi_conn: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    can_extents: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    extents: Option<unsafe extern "C" fn()>,
    can_cache: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    cache: Option<unsafe extern "C" fn()>,
    thread_model_fn: Option<unsafe extern "C" fn() -> c_int>,
    can_fast_zero: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    preconnect: Option<unsafe extern "C" fn(c_int) -> c_int>,
    get_ready: Option<unsafe extern "C" fn() -> c_int>,
    after_fork: Option<unsafe extern "C" fn() -> c_int>,
    list_exports: Option<unsafe extern "C" fn()>,
    default_export: Option<unsafe extern "C" fn()>,
    export_description: Option<unsafe extern "C" fn()>,
    cleanup: Option<unsafe extern "C" fn()>,
    block_size: Option<unsafe extern "C" fn(*mut c_void, *mut u32, *mut u32, *mut u32) -> c_int>,
}

const FLAG_MAY_TRIM: u32 = 1 << 0;
const FLAG_FUA: u32 = 1 << 1;
const FLAG_FAST_ZERO: u32 = 1 << 3;

fn errno() -> c_int {
    unsafe { *libc::__errno_location() }
}

fn clear_errno() {
    unsafe { *libc::__errno_location() = 0 }
}

fn config(root: &str, socket: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "audit3shim"
max_virtual_size = "2MiB"
device_block_size = 512
crypto_unit_size = 4096
shard_logical_size = "256KiB"
[crypto]
provider = "fake"
crypto_compatibility_id = "test-profile-v1"
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4104
[backing]
root = "{root}"
journal_emergency_reserve_bytes = "0B"
[nbd]
minimum_io = 4096
preferred_io = 4096
maximum_io = "8KiB"
threads = 2
[control]
socket = "{socket}"
"#
    )
}

#[test]
fn the_exported_c_abi_behaves_as_nbdkit_expects() {
    if std::env::var_os(CHILD_ENV).is_none() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().join("volume");
        let socket = dir.path().join("control.sock");
        let raw = config(root.to_str().unwrap(), socket.to_str().unwrap());
        let path = dir.path().join("volume.toml");
        std::fs::write(&path, &raw).unwrap();
        maki_nbdkit::daemon::create_volume_from_config_str(&raw).unwrap();
        let output = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "the_exported_c_abi_behaves_as_nbdkit_expects",
                "--nocapture",
            ])
            .env(CHILD_ENV, &path)
            .env_remove("NOTIFY_SOCKET")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success() && stdout.contains("AUDIT3 SHIM OK"),
            "native shim child failed:\n{stdout}\n{stderr}"
        );
        // The unload drained and released the volume: reattach in-process.
        let adapter = maki_nbdkit::adapter::NbdAdapter::open_config(path.to_str().unwrap()).unwrap();
        let mut data = vec![0u8; 20 * 1024];
        adapter.pread(&mut data, 4096).unwrap();
        let mut expected: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8 | 1).collect();
        expected[4096..8192].fill(0);
        assert_eq!(data, expected, "data written through the C ABI");
        adapter.shutdown().unwrap();
        return;
    }

    let config_path = std::env::var(CHILD_ENV).unwrap();
    let plugin_path = CString::new(native_plugin::path().to_str().unwrap()).unwrap();
    unsafe {
        let lib = libc::dlopen(plugin_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL);
        assert!(!lib.is_null(), "dlopen failed");
        let init = libc::dlsym(lib, c"plugin_init".as_ptr());
        assert!(!init.is_null());
        let init: extern "C" fn() -> *const Plugin = std::mem::transmute(init);
        let p = &*init();
        assert_eq!(p.struct_size as usize, std::mem::size_of::<Plugin>());
        assert_eq!(p.api_version, 2);
        assert_eq!(p.thread_model, 3, "PARALLEL");
        assert_eq!(p.errno_is_preserved, 1);
        assert!(p.can_multi_conn.is_none() && p.can_extents.is_none() && p.can_cache.is_none());
        assert!(p.magic_config_key.is_null());

        let config = p.config.unwrap();
        let key = CString::new("config").unwrap();
        let value = CString::new(config_path.clone()).unwrap();
        assert_eq!(config(c"bogus".as_ptr(), c"x".as_ptr()), -1);
        assert_eq!(config(key.as_ptr(), value.as_ptr()), 0);
        assert_eq!(p.config_complete.unwrap()(), 0);
        // nbdkit never opens before after_fork, but a NULL is the safe answer.
        assert!(p.open.unwrap()(0).is_null(), "open before readiness");
        assert_eq!(p.after_fork.unwrap()(), 0, "after_fork failed");

        let open = p.open.unwrap();
        let h = open(0);
        assert!(!h.is_null());
        clear_errno();
        assert!(open(0).is_null(), "second connection admitted");
        assert_eq!(errno(), libc::EBUSY);

        assert_eq!(p.get_size.unwrap()(h), 2 << 20);
        let (mut min, mut pref, mut max) = (0u32, 0u32, 0u32);
        assert_eq!(p.block_size.unwrap()(h, &mut min, &mut pref, &mut max), 0);
        assert_eq!((min, pref, max), (4096, 4096, 8192));
        assert_eq!(p.can_write.unwrap()(h), 1);
        assert_eq!(p.can_flush.unwrap()(h), 1);
        assert_eq!(p.can_trim.unwrap()(h), 0, "v2 volume must not advertise trim");
        assert_eq!(p.can_zero.unwrap()(h), 1);
        assert_eq!(p.can_fast_zero.unwrap()(h), 0);
        assert_eq!(p.can_fua.unwrap()(h), 2, "NBDKIT_FUA_NATIVE");

        let pwrite = p.pwrite.unwrap();
        let pread = p.pread.unwrap();
        let zero = p.zero.unwrap();
        // Misaligned below the advertised minimum: EINVAL, nothing applied.
        let junk = vec![0xEEu8; 4096];
        clear_errno();
        assert_eq!(pwrite(h, junk.as_ptr().cast(), 4096, 512, FLAG_FUA), -1);
        assert_eq!(errno(), libc::EINVAL);

        let data: Vec<u8> = (0..20 * 1024).map(|i| (i % 251) as u8 | 1).collect();
        assert_eq!(
            pwrite(h, data.as_ptr().cast(), data.len() as u32, 4096, FLAG_FUA),
            0
        );
        let mut back = vec![0u8; data.len()];
        assert_eq!(
            pread(h, back.as_mut_ptr().cast(), back.len() as u32, 4096, 0),
            0
        );
        assert_eq!(back, data);

        // FAST_ZERO (not advertised): fail fast with ENOTSUP, write nothing.
        clear_errno();
        assert_eq!(zero(h, 4096, 8192, FLAG_FAST_ZERO | FLAG_MAY_TRIM), -1);
        assert_eq!(errno(), libc::ENOTSUP);
        assert_eq!(pread(h, back.as_mut_ptr().cast(), 4096, 8192, 0), 0);
        assert_eq!(&back[..4096], &data[4096..8192]);
        assert_eq!(zero(h, 4096, 8192, FLAG_MAY_TRIM | FLAG_FUA), 0);
        assert_eq!(pread(h, back.as_mut_ptr().cast(), 4096, 8192, 0), 0);
        assert!(back[..4096].iter().all(|b| *b == 0));
        assert_eq!(p.flush.unwrap()(h, 0), 0);

        // Out of range for the engine (nbdkit normally refuses first).
        clear_errno();
        assert_eq!(pread(h, back.as_mut_ptr().cast(), 8192, (2 << 20) - 4096, 0), -1);
        assert_eq!(errno(), libc::EINVAL);

        p.close.unwrap()(h);
        let h2 = open(0);
        assert!(!h2.is_null(), "close did not release the connection slot");
        p.close.unwrap()(h2);

        p.unload.unwrap()();
        // After unload the shared handle refuses I/O with ESHUTDOWN.
        clear_errno();
        assert_eq!(pread(h, back.as_mut_ptr().cast(), 4096, 0, 0), -1);
        assert_eq!(errno(), libc::ESHUTDOWN);

        // nbdkit dlclose()s the plugin right after unload. The adapter's
        // Tokio runtime (a never-dropped static) still has threads parked in
        // the library's code; the mapping must survive the dlclose or those
        // threads fault when they next wake (blocking-pool keep-alive).
        assert_eq!(libc::dlclose(lib), 0);
        let maps = std::fs::read_to_string("/proc/self/maps").unwrap();
        let still_mapped = maps.lines().any(|l| l.ends_with("libmaki_nbdkit.so"));
        println!("AUDIT3 plugin still mapped after dlclose: {still_mapped}");
        assert!(still_mapped, "dlclose unmapped the plugin under live runtime threads");
    }
    println!("AUDIT3 SHIM OK");
}
