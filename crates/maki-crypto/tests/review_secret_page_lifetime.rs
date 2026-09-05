//! BUG-006: page locks are shared by allocations on the same OS page.
//! Isolate each case because page-locking policy and rlimits are process-wide.

#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use maki_crypto::secret::{page_lock_failures, set_page_locking};
use maki_crypto::SecretBuffer;

struct InspectDeallocation;

static WATCHED_ALLOCATION: AtomicUsize = AtomicUsize::new(0);
static ZEROIZED: AtomicBool = AtomicBool::new(false);

// SAFETY: allocation and deallocation always delegate to the same System
// allocator. The sole inspected allocation is still live before deallocation
// and the test initializes its entire capacity before registering it.
unsafe impl GlobalAlloc for InspectDeallocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if WATCHED_ALLOCATION.load(Ordering::SeqCst) == ptr as usize {
            let bytes = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            ZEROIZED.store(bytes.iter().all(|byte| *byte == 0), Ordering::SeqCst);
            WATCHED_ALLOCATION.store(0, Ordering::SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectDeallocation = InspectDeallocation;

fn kernel_page_locked(address: usize) -> bool {
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut contains_address = false;
    for line in maps.lines() {
        if let Some((start, end)) = line
            .split_whitespace()
            .next()
            .and_then(|s| s.split_once('-'))
        {
            let start = usize::from_str_radix(start, 16).unwrap();
            let end = usize::from_str_radix(end, 16).unwrap();
            contains_address = (start..end).contains(&address);
        } else if contains_address && line.starts_with("VmFlags:") {
            return line.split_whitespace().any(|flag| flag == "lo");
        }
    }
    false
}

fn shared_page_case(export: bool, duplicate: bool) {
    // SAFETY: sysconf has no pointer arguments.
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let seed = SecretBuffer::from_slice(&[0xA5; 64]);
    assert!(
        seed.is_page_locked(),
        "this Linux regression requires mlock"
    );
    let mut buffers: Vec<_> = (0..128)
        .map(|_| {
            Some(if duplicate {
                seed.duplicate()
            } else {
                SecretBuffer::from_vec(vec![0xA5; 64])
            })
        })
        .collect();
    let (a, b) = (0..buffers.len())
        .find_map(|a| {
            let first = buffers[a].as_ref().unwrap().expose().as_ptr() as usize;
            (a + 1..buffers.len()).find_map(|b| {
                let second = buffers[b].as_ref().unwrap().expose().as_ptr() as usize;
                (first / page_size == (first + 63) / page_size
                    && first / page_size == second / page_size
                    && first / page_size == (second + 63) / page_size)
                    .then_some((a, b))
            })
        })
        .expect("the allocator should place small allocations on a shared page");
    let address = buffers[b].as_ref().unwrap().expose().as_ptr() as usize;
    assert!(kernel_page_locked(address));
    let removed = buffers[a].take().unwrap();
    let exported = if export {
        let bytes = removed.into_vec();
        assert_eq!(bytes, vec![0xA5; 64], "into_vec must preserve the bytes");
        Some(bytes)
    } else {
        drop(removed);
        None
    };
    let surviving = buffers[b].as_ref().unwrap();
    assert!(surviving.is_page_locked());
    assert!(
        kernel_page_locked(address),
        "releasing one allocation unlocked a live peer"
    );
    assert_eq!(surviving.expose(), &[0xA5; 64]);
    drop(seed);
    drop(buffers);
    assert!(
        !kernel_page_locked(address),
        "the last owner must release the page"
    );
    drop(exported);
}

fn zeroization_case() {
    let mut bytes = vec![0xC7; 256];
    bytes.truncate(64); // Include initialized secret bytes in spare capacity.
    WATCHED_ALLOCATION.store(bytes.as_ptr() as usize, Ordering::SeqCst);
    drop(SecretBuffer::from_vec(bytes));
    assert_eq!(
        WATCHED_ALLOCATION.load(Ordering::SeqCst),
        0,
        "allocation was released"
    );
    assert!(
        ZEROIZED.load(Ordering::SeqCst),
        "all secret capacity must be zero before deallocation"
    );
}

fn locking_failure_case() {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: both calls use a valid rlimit pointer and change this child only.
    assert_eq!(
        unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) },
        0
    );
    limit.rlim_cur = 0;
    assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &limit) }, 0);
    let before = page_lock_failures();
    let buffer = SecretBuffer::zeroed(8192);
    assert!(!buffer.is_page_locked());
    assert_eq!(page_lock_failures(), before + 1);
    drop(buffer);
    zeroization_case();
}

#[test]
fn secret_page_lifetimes() {
    const CASE_ENV: &str = "MAKI_SECRET_PAGE_TEST_CASE";
    if let Ok(case) = std::env::var(CASE_ENV) {
        set_page_locking(true);
        match case.as_str() {
            "drop" => shared_page_case(false, false),
            "into_vec" => shared_page_case(true, false),
            "duplicate" => shared_page_case(false, true),
            "zeroize" => zeroization_case(),
            "locking_failure" => locking_failure_case(),
            _ => panic!("unknown case"),
        }
        return;
    }

    let mut failures = Vec::new();
    for case in [
        "drop",
        "into_vec",
        "duplicate",
        "zeroize",
        "locking_failure",
    ] {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "secret_page_lifetimes", "--nocapture"])
            .env(CASE_ENV, case)
            .output()
            .unwrap();
        if !output.status.success() {
            failures.push(case);
            eprintln!(
                "{case}: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }
    assert!(failures.is_empty(), "failed lifetime cases: {failures:?}");
}
