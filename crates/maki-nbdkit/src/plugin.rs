//! nbdkit C ABI shim (Linux only): exports `plugin_init` for
//! `nbdkit /usr/lib/maki/maki-nbdkit.so config=/etc/maki/volumes/<v>.toml`.
//!
//! Layout notes:
//! - Field order follows nbdkit-plugin.h API version 2 for the fields we
//!   populate; `_struct_size` includes the block_size callback so clients
//!   can negotiate the configured limits. Other optional callbacks stay
//!   NULL (multi-conn OFF, zero emulated via pwrite, trim absent).
//! - The tokio runtime is created lazily at first `open`, which happens
//!   after nbdkit forks — equivalent to the `after_fork` hook without
//!   depending on newer struct fields.
//! - MUST be layout-verified against the distribution's nbdkit-plugin.h in
//!   Linux qualification before production use (see docs/testing.md).

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::OnceLock;

use parking_lot::Mutex;

use crate::adapter::NbdAdapter;

/// Values from `nbdkit-common.h` / `nbdkit-plugin.h` the shim depends on.
/// `tests/review_abi.rs` compiles a C probe against the installed header
/// and checks every one of them plus the struct layout (third review,
/// F08: `can_fua` used to return 1, which is `NBDKIT_FUA_EMULATE`).
pub const NBDKIT_API_VERSION: c_int = 2;
pub const NBDKIT_THREAD_MODEL_PARALLEL: c_int = 3;
pub const NBDKIT_FUA_NONE: c_int = 0;
pub const NBDKIT_FUA_EMULATE: c_int = 1;
pub const NBDKIT_FUA_NATIVE: c_int = 2;
/// `NBDKIT_FLAG_FUA` (`1 << 1`): the request flag on `pwrite`.
pub const NBDKIT_FLAG_FUA: u32 = 1 << 1;

const THREAD_MODEL_PARALLEL: c_int = NBDKIT_THREAD_MODEL_PARALLEL;
const API_VERSION: c_int = NBDKIT_API_VERSION;

static CONFIG_PATH: Mutex<Option<String>> = Mutex::new(None);
static ADAPTER: OnceLock<NbdAdapter> = OnceLock::new();

fn adapter() -> Option<&'static NbdAdapter> {
    if let Some(a) = ADAPTER.get() {
        return Some(a);
    }
    let path = CONFIG_PATH.lock().clone()?;
    match NbdAdapter::open_config(&path) {
        Ok(a) => {
            let _ = ADAPTER.set(a);
            ADAPTER.get()
        }
        Err(e) => {
            eprintln!("maki-nbdkit: attach failed: {e}");
            None
        }
    }
}

unsafe extern "C" fn config(key: *const c_char, value: *const c_char) -> c_int {
    let key = unsafe { CStr::from_ptr(key) }.to_string_lossy();
    let value = unsafe { CStr::from_ptr(value) }.to_string_lossy();
    if key == "config" {
        *CONFIG_PATH.lock() = Some(value.into_owned());
        0
    } else {
        eprintln!("maki-nbdkit: unknown parameter {key}");
        -1
    }
}

unsafe extern "C" fn config_complete() -> c_int {
    if CONFIG_PATH.lock().is_none() {
        eprintln!("maki-nbdkit: missing config=<path> parameter");
        return -1;
    }
    0
}

unsafe extern "C" fn open(_readonly: c_int) -> *mut c_void {
    match adapter() {
        Some(a) => a as *const NbdAdapter as *mut c_void,
        None => std::ptr::null_mut(),
    }
}

unsafe extern "C" fn close(_handle: *mut c_void) {}

unsafe extern "C" fn get_size(handle: *mut c_void) -> i64 {
    let a = unsafe { &*(handle as *const NbdAdapter) };
    a.get_size() as i64
}

unsafe extern "C" fn block_size(
    handle: *mut c_void,
    minimum: *mut u32,
    preferred: *mut u32,
    maximum: *mut u32,
) -> c_int {
    let a = unsafe { &*(handle as *const NbdAdapter) };
    let sizes = a.block_sizes();
    // nbdkit supplies valid output pointers for the negotiation callback.
    unsafe {
        *minimum = sizes.0;
        *preferred = sizes.1;
        *maximum = sizes.2;
    }
    0
}

unsafe extern "C" fn can_write(_h: *mut c_void) -> c_int {
    1
}

unsafe extern "C" fn can_flush(_h: *mut c_void) -> c_int {
    1
}

unsafe extern "C" fn is_rotational(_h: *mut c_void) -> c_int {
    0
}

unsafe extern "C" fn can_trim(_h: *mut c_void) -> c_int {
    0
}

unsafe extern "C" fn can_zero(_h: *mut c_void) -> c_int {
    0 // nbdkit falls back to pwrite of zeros
}

unsafe extern "C" fn can_fua(_h: *mut c_void) -> c_int {
    // Native: the FUA flag reaches `pwrite_v2` and the engine syncs the
    // request's records (SPEC 24). Returning EMULATE (1) would make nbdkit
    // issue a full flush after every FUA write instead.
    NBDKIT_FUA_NATIVE
}

/// What [`can_fua`] answers (exposed for the ABI test).
pub fn can_fua_value() -> c_int {
    // SAFETY: the handle is unused.
    unsafe { can_fua(std::ptr::null_mut()) }
}

fn set_errno(errno: i32) {
    // errno_is_preserved = 1: nbdkit reads errno on failure.
    unsafe {
        *libc_errno_location() = errno;
    }
}

extern "C" {
    #[cfg_attr(target_os = "linux", link_name = "__errno_location")]
    fn libc_errno_location() -> *mut c_int;
}

unsafe extern "C" fn pread_v2(
    handle: *mut c_void,
    buf: *mut c_void,
    count: u32,
    offset: u64,
    _flags: u32,
) -> c_int {
    let a = unsafe { &*(handle as *const NbdAdapter) };
    let slice = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, count as usize) };
    match a.pread(slice, offset) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(e.errno);
            -1
        }
    }
}

unsafe extern "C" fn pwrite_v2(
    handle: *mut c_void,
    buf: *const c_void,
    count: u32,
    offset: u64,
    flags: u32,
) -> c_int {
    let a = unsafe { &*(handle as *const NbdAdapter) };
    let slice = unsafe { std::slice::from_raw_parts(buf as *const u8, count as usize) };
    let fua = flags & NBDKIT_FLAG_FUA != 0;
    match a.pwrite(slice, offset, fua) {
        Ok(()) => 0,
        Err(e) => {
            set_errno(e.errno);
            -1
        }
    }
}

unsafe extern "C" fn flush_v2(handle: *mut c_void, _flags: u32) -> c_int {
    let a = unsafe { &*(handle as *const NbdAdapter) };
    match a.flush() {
        Ok(()) => 0,
        Err(e) => {
            set_errno(e.errno);
            -1
        }
    }
}

unsafe extern "C" fn unload() {
    if let Some(a) = ADAPTER.get() {
        let _ = a.shutdown();
    }
}

/// Mirror of the nbdkit_plugin v2 prefix (see module docs).
#[repr(C)]
struct nbdkit_plugin {
    _struct_size: u64,
    _api_version: c_int,
    _thread_model: c_int,
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
    _pread_v1: Option<unsafe extern "C" fn(*mut c_void, *mut c_void, u32, u64) -> c_int>,
    _pwrite_v1: Option<unsafe extern "C" fn(*mut c_void, *const c_void, u32, u64) -> c_int>,
    _flush_v1: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    _trim_v1: Option<unsafe extern "C" fn(*mut c_void, u32, u64) -> c_int>,
    _zero_v1: Option<unsafe extern "C" fn(*mut c_void, u32, u64, c_int) -> c_int>,
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
    extents: Option<unsafe extern "C" fn(*mut c_void, u32, u64, u32, *mut c_void) -> c_int>,
    can_cache: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    cache: Option<unsafe extern "C" fn(*mut c_void, u32, u64, u32) -> c_int>,
    thread_model: Option<unsafe extern "C" fn() -> c_int>,
    can_fast_zero: Option<unsafe extern "C" fn(*mut c_void) -> c_int>,
    preconnect: Option<unsafe extern "C" fn(c_int) -> c_int>,
    get_ready: Option<unsafe extern "C" fn() -> c_int>,
    after_fork: Option<unsafe extern "C" fn() -> c_int>,
    list_exports: Option<unsafe extern "C" fn(c_int, c_int, *mut c_void) -> c_int>,
    default_export: Option<unsafe extern "C" fn(c_int, c_int) -> *const c_char>,
    export_description: Option<unsafe extern "C" fn(*mut c_void) -> *const c_char>,
    cleanup: Option<unsafe extern "C" fn()>,
    block_size: Option<unsafe extern "C" fn(*mut c_void, *mut u32, *mut u32, *mut u32) -> c_int>,
}

unsafe impl Sync for nbdkit_plugin {}

static PLUGIN: nbdkit_plugin = nbdkit_plugin {
    _struct_size: std::mem::size_of::<nbdkit_plugin>() as u64,
    _api_version: API_VERSION,
    _thread_model: THREAD_MODEL_PARALLEL,
    name: c"maki".as_ptr(),
    longname: c"Maki encrypted volume".as_ptr(),
    version: c"0.1.0".as_ptr(),
    description: c"Crash-consistent encrypted block device (see SPEC.md)".as_ptr(),
    load: None,
    unload: Some(unload),
    config: Some(config),
    config_complete: Some(config_complete),
    config_help: c"config=<PATH>    volume TOML configuration".as_ptr(),
    open: Some(open),
    close: Some(close),
    get_size: Some(get_size),
    can_write: Some(can_write),
    can_flush: Some(can_flush),
    is_rotational: Some(is_rotational),
    can_trim: Some(can_trim),
    _pread_v1: None,
    _pwrite_v1: None,
    _flush_v1: None,
    _trim_v1: None,
    _zero_v1: None,
    errno_is_preserved: 1,
    dump_plugin: None,
    can_zero: Some(can_zero),
    can_fua: Some(can_fua),
    pread: Some(pread_v2),
    pwrite: Some(pwrite_v2),
    flush: Some(flush_v2),
    trim: None,
    zero: None,
    magic_config_key: std::ptr::null(),
    can_multi_conn: None,
    can_extents: None,
    extents: None,
    can_cache: None,
    cache: None,
    thread_model: None,
    can_fast_zero: None,
    preconnect: None,
    get_ready: None,
    after_fork: None,
    list_exports: None,
    default_export: None,
    export_description: None,
    cleanup: None,
    block_size: Some(block_size),
};

#[no_mangle]
extern "C" fn plugin_init() -> *const nbdkit_plugin {
    &PLUGIN
}

/// The shim's view of the C ABI: byte offset of every `nbdkit_plugin`
/// field it populates (or must skip), the prefix size it declares, and the
/// constants it relies on. `tests/review_abi.rs` compares this with a C
/// probe compiled against the distribution's header.
pub fn abi_layout() -> Vec<(&'static str, usize)> {
    use std::mem::offset_of;
    vec![
        ("_struct_size", offset_of!(nbdkit_plugin, _struct_size)),
        ("_api_version", offset_of!(nbdkit_plugin, _api_version)),
        ("_thread_model", offset_of!(nbdkit_plugin, _thread_model)),
        ("name", offset_of!(nbdkit_plugin, name)),
        ("longname", offset_of!(nbdkit_plugin, longname)),
        ("version", offset_of!(nbdkit_plugin, version)),
        ("description", offset_of!(nbdkit_plugin, description)),
        ("load", offset_of!(nbdkit_plugin, load)),
        ("unload", offset_of!(nbdkit_plugin, unload)),
        ("config", offset_of!(nbdkit_plugin, config)),
        (
            "config_complete",
            offset_of!(nbdkit_plugin, config_complete),
        ),
        ("config_help", offset_of!(nbdkit_plugin, config_help)),
        ("open", offset_of!(nbdkit_plugin, open)),
        ("close", offset_of!(nbdkit_plugin, close)),
        ("get_size", offset_of!(nbdkit_plugin, get_size)),
        ("can_write", offset_of!(nbdkit_plugin, can_write)),
        ("can_flush", offset_of!(nbdkit_plugin, can_flush)),
        ("is_rotational", offset_of!(nbdkit_plugin, is_rotational)),
        ("can_trim", offset_of!(nbdkit_plugin, can_trim)),
        ("_pread_v1", offset_of!(nbdkit_plugin, _pread_v1)),
        ("_pwrite_v1", offset_of!(nbdkit_plugin, _pwrite_v1)),
        ("_flush_v1", offset_of!(nbdkit_plugin, _flush_v1)),
        ("_trim_v1", offset_of!(nbdkit_plugin, _trim_v1)),
        ("_zero_v1", offset_of!(nbdkit_plugin, _zero_v1)),
        (
            "errno_is_preserved",
            offset_of!(nbdkit_plugin, errno_is_preserved),
        ),
        ("dump_plugin", offset_of!(nbdkit_plugin, dump_plugin)),
        ("can_zero", offset_of!(nbdkit_plugin, can_zero)),
        ("can_fua", offset_of!(nbdkit_plugin, can_fua)),
        ("pread", offset_of!(nbdkit_plugin, pread)),
        ("pwrite", offset_of!(nbdkit_plugin, pwrite)),
        ("flush", offset_of!(nbdkit_plugin, flush)),
        ("trim", offset_of!(nbdkit_plugin, trim)),
        ("zero", offset_of!(nbdkit_plugin, zero)),
        (
            "magic_config_key",
            offset_of!(nbdkit_plugin, magic_config_key),
        ),
        ("can_multi_conn", offset_of!(nbdkit_plugin, can_multi_conn)),
        ("can_extents", offset_of!(nbdkit_plugin, can_extents)),
        ("extents", offset_of!(nbdkit_plugin, extents)),
        ("can_cache", offset_of!(nbdkit_plugin, can_cache)),
        ("cache", offset_of!(nbdkit_plugin, cache)),
        ("thread_model", offset_of!(nbdkit_plugin, thread_model)),
        ("can_fast_zero", offset_of!(nbdkit_plugin, can_fast_zero)),
        ("preconnect", offset_of!(nbdkit_plugin, preconnect)),
        ("get_ready", offset_of!(nbdkit_plugin, get_ready)),
        ("after_fork", offset_of!(nbdkit_plugin, after_fork)),
        ("list_exports", offset_of!(nbdkit_plugin, list_exports)),
        ("default_export", offset_of!(nbdkit_plugin, default_export)),
        (
            "export_description",
            offset_of!(nbdkit_plugin, export_description),
        ),
        ("cleanup", offset_of!(nbdkit_plugin, cleanup)),
        ("block_size", offset_of!(nbdkit_plugin, block_size)),
        ("sizeof_prefix", std::mem::size_of::<nbdkit_plugin>()),
        ("NBDKIT_API_VERSION", NBDKIT_API_VERSION as usize),
        (
            "NBDKIT_THREAD_MODEL_PARALLEL",
            NBDKIT_THREAD_MODEL_PARALLEL as usize,
        ),
        ("NBDKIT_FUA_NONE", NBDKIT_FUA_NONE as usize),
        ("NBDKIT_FUA_EMULATE", NBDKIT_FUA_EMULATE as usize),
        ("NBDKIT_FUA_NATIVE", NBDKIT_FUA_NATIVE as usize),
        ("NBDKIT_FLAG_FUA", NBDKIT_FLAG_FUA as usize),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fua_is_advertised_as_native_not_emulated() {
        assert_eq!(can_fua_value(), NBDKIT_FUA_NATIVE);
        assert_eq!(NBDKIT_FUA_NATIVE, 2, "nbdkit-common.h: NBDKIT_FUA_NATIVE 2");
        assert_ne!(can_fua_value(), NBDKIT_FUA_EMULATE);
    }

    /// The published prefix ends right after `block_size` (nbdkit >= 1.30),
    /// the last callback the shim populates: 384 bytes on LP64, with
    /// `block_size` at offset 376 (BUG-011; the C probe in
    /// `tests/review_abi.rs` confirms both against the installed header).
    #[test]
    fn declared_prefix_ends_after_the_block_size_callback() {
        let layout = abi_layout();
        let of = |n: &str| layout.iter().find(|(k, _)| *k == n).unwrap().1;
        assert_eq!(
            of("sizeof_prefix"),
            of("block_size") + std::mem::size_of::<usize>()
        );
        assert!(of("block_size") > of("zero"));
        assert_eq!(of("_struct_size"), 0);
        assert_eq!(PLUGIN._struct_size as usize, of("sizeof_prefix"));
    }
}
