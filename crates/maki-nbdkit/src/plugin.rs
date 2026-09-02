//! nbdkit C ABI shim (Linux only): exports `plugin_init` for
//! `nbdkit /usr/lib/maki/maki-nbdkit.so config=/etc/maki/volumes/<v>.toml`.
//!
//! Layout notes:
//! - Field order follows nbdkit-plugin.h API version 2 for the fields we
//!   populate; `_struct_size` stops after the v2 rpc callbacks, so later
//!   optional fields (`can_multi_conn`, `block_size`, …) read as NULL in
//!   nbdkit — their defaults match our requirements (multi-conn OFF, zero
//!   emulated via pwrite, trim absent).
//! - The tokio runtime is created lazily at first `open`, which happens
//!   after nbdkit forks — equivalent to the `after_fork` hook without
//!   depending on newer struct fields.
//! - MUST be layout-verified against the distribution's nbdkit-plugin.h in
//!   Linux CI before production use (see docs/phase-6.md).

#![allow(non_camel_case_types)]

use std::ffi::{c_char, c_int, c_void, CStr};
use std::sync::OnceLock;

use parking_lot::Mutex;

use crate::adapter::NbdAdapter;

const THREAD_MODEL_PARALLEL: c_int = 3;
const API_VERSION: c_int = 2;

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
    1 // NBDKIT_FUA_NATIVE
}

const NBDKIT_FLAG_FUA: u32 = 2;

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
};

#[no_mangle]
extern "C" fn plugin_init() -> *const nbdkit_plugin {
    &PLUGIN
}
