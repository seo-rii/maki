//! Every call of a fuzz entry function runs its input on the calling
//! thread: it starts no thread, and it frees every heap block it allocates
//! before it returns.
//!
//! libFuzzer runs every input of a run in one process, about 10 million of
//! them in each process of a qualification shard, and under
//! AddressSanitizer that process's memory grows with every thread it has
//! started, also once the thread has ended. `nbd_handshake` ran its server
//! side on a thread of its own per input: all eight processes of its
//! qualification passed `-rss_limit_mb=2048` after about 10 million inputs
//! each, and the inputs libFuzzer wrote as out-of-memory include the empty
//! one. A server thread kept for every input is no way out either:
//! libFuzzer counts the mallocs and frees of each call, in every thread,
//! runs a call that ended with more mallocs than frees again and then
//! checks the process for leaks, and after 1,000 such checks it stops
//! looking for leaks per input. The kept thread freed each input's memory
//! after the call had returned.
//!
//! This test binary counts both. It defines `pthread_create`, which the
//! standard library's `std::thread` calls (the definition in the executable
//! is the one its references resolve to), counts the call and hands it to
//! the C library's own (`dlsym(RTLD_NEXT)`); and its global allocator
//! counts every allocation and free, and on which thread it was made.
//! Every committed seed of every target (as `review_fuzz_corpus.rs` replays
//! them) is called once, so that what a target sets up on its first input
//! (a `OnceLock`, a callsite's registration) is not counted, and then
//! [`CALLS`] more times, each of which must start no thread, make no
//! allocation or free on another thread, and free as many blocks as it
//! allocates. A pattern that starts a thread or keeps a block only every
//! more than [`CALLS`] calls is not seen. The counts are the process's,
//! so this file holds one test: another test running beside it would be
//! counted too.
#![cfg(target_os = "linux")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::ffi::{c_char, c_int, c_void};
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use maki_fuzz_harness::{seeds, TARGETS};

/// Calls of each seed that are counted, after its first.
const CALLS: usize = 8;

/// Threads started in this process, by anything.
static THREADS: AtomicU64 = AtomicU64::new(0);

/// The C library's `pthread_create`.
static REAL_PTHREAD_CREATE: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());

type ThreadStart = unsafe extern "C" fn(*mut c_void) -> *mut c_void;
type PthreadCreate =
    unsafe extern "C" fn(*mut c_void, *const c_void, ThreadStart, *mut c_void) -> c_int;

extern "C" {
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// glibc's and musl's `RTLD_NEXT`: the next object in the search order
/// after the caller's.
const RTLD_NEXT: *mut c_void = -1isize as *mut c_void;

/// Every thread `std::thread` starts in this binary: count it, then start
/// it with the C library's `pthread_create`. The pointer arguments are
/// passed on unchanged.
#[no_mangle]
unsafe extern "C" fn pthread_create(
    thread: *mut c_void,
    attributes: *const c_void,
    start: ThreadStart,
    argument: *mut c_void,
) -> c_int {
    THREADS.fetch_add(1, Ordering::SeqCst);
    let mut real = REAL_PTHREAD_CREATE.load(Ordering::Acquire);
    if real.is_null() {
        // SAFETY: a NUL-terminated name; dlsym has no other precondition.
        real = unsafe { dlsym(RTLD_NEXT, c"pthread_create".as_ptr()) };
        if real.is_null() {
            // No thread can be started; nothing here can report it.
            std::process::abort();
        }
        REAL_PTHREAD_CREATE.store(real, Ordering::Release);
    }
    // SAFETY: the C library's `pthread_create`, whose signature this is.
    let real: PthreadCreate = unsafe { std::mem::transmute::<*mut c_void, PthreadCreate>(real) };
    // SAFETY: the caller's arguments, as the caller passed them.
    unsafe { real(thread, attributes, start, argument) }
}

/// The global allocator: the system's, counted.
struct Counted;

#[global_allocator]
static ALLOCATOR: Counted = Counted;

/// Whether a call is being counted.
static COUNTING: AtomicBool = AtomicBool::new(false);
/// What the calling thread allocated and freed while a call was counted.
static ALLOCATED: AtomicU64 = AtomicU64::new(0);
static FREED: AtomicU64 = AtomicU64::new(0);
/// What other threads allocated or freed while a call was counted.
static ELSEWHERE: AtomicU64 = AtomicU64::new(0);

thread_local! {
    /// Whether this thread is the one whose call is counted. A `const`
    /// thread local without a destructor never allocates.
    static CALLER: Cell<bool> = const { Cell::new(false) };
}

fn note(counter: &AtomicU64) {
    if !COUNTING.load(Ordering::SeqCst) {
        return;
    }
    if CALLER.try_with(Cell::get).unwrap_or(false) {
        counter.fetch_add(1, Ordering::SeqCst);
    } else {
        ELSEWHERE.fetch_add(1, Ordering::SeqCst);
    }
}

// SAFETY: every method hands its arguments to `System` unchanged and only
// adds to atomic counters, which allocates nothing.
unsafe impl GlobalAlloc for Counted {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note(&ALLOCATED);
        // SAFETY: the caller's layout, as `GlobalAlloc::alloc` requires.
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note(&ALLOCATED);
        // SAFETY: as for `alloc`.
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn dealloc(&self, block: *mut u8, layout: Layout) {
        note(&FREED);
        // SAFETY: a block this allocator returned, with its layout.
        unsafe { System.dealloc(block, layout) }
    }

    // A resize neither adds a block nor removes one (libFuzzer counts it as
    // a malloc and a free).
    unsafe fn realloc(&self, block: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        // SAFETY: as for `dealloc`, with the caller's new size.
        unsafe { System.realloc(block, layout, size) }
    }
}

/// What one counted call did.
#[derive(Debug, PartialEq, Eq)]
struct Call {
    threads: u64,
    allocated: u64,
    freed: u64,
    elsewhere: u64,
}

impl Call {
    const CLEAN: Self = Self {
        threads: 0,
        allocated: 0,
        freed: 0,
        elsewhere: 0,
    };

    fn is_clean(&self) -> bool {
        self.threads == 0 && self.allocated == self.freed && self.elsewhere == 0
    }
}

/// Run `call` on this thread with its threads and heap blocks counted.
fn counted(call: impl FnOnce()) -> Call {
    for counter in [&ALLOCATED, &FREED, &ELSEWHERE] {
        counter.store(0, Ordering::SeqCst);
    }
    let threads = THREADS.load(Ordering::SeqCst);
    CALLER.with(|caller| caller.set(true));
    COUNTING.store(true, Ordering::SeqCst);
    call();
    COUNTING.store(false, Ordering::SeqCst);
    CALLER.with(|caller| caller.set(false));
    Call {
        threads: THREADS.load(Ordering::SeqCst) - threads,
        allocated: ALLOCATED.load(Ordering::SeqCst),
        freed: FREED.load(Ordering::SeqCst),
        elsewhere: ELSEWHERE.load(Ordering::SeqCst),
    }
}

/// The seeds of `target` as `review_fuzz_corpus.rs` replays them: the
/// committed files, or on a big-endian host the generator's own for a
/// target whose committed seeds are a little-endian host's.
fn seeds_of(target: &str) -> Vec<(String, Vec<u8>)> {
    if cfg!(target_endian = "big") && seeds::LITTLE_ENDIAN.contains(&target) {
        return seeds::all()
            .into_iter()
            .filter(|seed| seed.target == target)
            .map(|seed| (seed.name, seed.bytes))
            .collect();
    }
    let directory = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../seeds")
        .join(target);
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(&directory)
        .unwrap_or_else(|error| panic!("{}: {error}", directory.display()))
        .map(|entry| {
            let entry = entry.unwrap();
            let name = entry.file_name().into_string().unwrap();
            (name, std::fs::read(entry.path()).unwrap())
        })
        .collect();
    files.sort();
    files
}

/// The counts see what they must: a thread started, a block kept, a block
/// freed, and blocks another thread allocates and frees while a call is
/// counted. Without this, a binary whose `std::thread` did not reach the
/// `pthread_create` above, or whose allocator was not this one, would pass
/// every seed.
fn the_counts_see_threads_and_blocks() {
    let started = counted(|| std::thread::spawn(|| ()).join().unwrap());
    assert_eq!(
        started.threads, 1,
        "a thread started and joined was counted as {started:?}"
    );
    let mut kept = None;
    let keeping = counted(|| kept = Some(std::hint::black_box(Box::new(0u64))));
    assert_eq!(
        (keeping.allocated, keeping.freed),
        (1, 0),
        "a block kept was counted as {keeping:?}"
    );
    let freeing = counted(|| drop(kept.take()));
    assert_eq!(
        (freeing.allocated, freeing.freed),
        (0, 1),
        "a block freed was counted as {freeing:?}"
    );
    // A thread started before the count allocates and frees a block while
    // the counted call waits for it.
    let turns = Arc::new((Barrier::new(2), Barrier::new(2)));
    let helper = {
        let turns = Arc::clone(&turns);
        std::thread::spawn(move || {
            turns.0.wait();
            drop(std::hint::black_box(Box::new(0u64)));
            turns.1.wait();
        })
    };
    let beside = counted(|| {
        turns.0.wait();
        turns.1.wait();
    });
    helper.join().unwrap();
    // At least its block; its own exit may free more meanwhile.
    assert!(
        beside.elsewhere >= 2 && (beside.threads, beside.allocated, beside.freed) == (0, 0, 0),
        "a block another thread allocated and freed was counted as {beside:?}"
    );
    assert_eq!(counted(|| ()), Call::CLEAN);
}

#[test]
fn entry_calls_start_no_thread_and_free_what_they_allocate() {
    the_counts_see_threads_and_blocks();
    let mut replayed = 0;
    let mut unclean = Vec::new();
    for target in TARGETS {
        let Some(entry) = target.entry else {
            continue;
        };
        for (name, bytes) in seeds_of(target.name) {
            entry(&bytes);
            let calls: Vec<Call> = (0..CALLS)
                .map(|_| {
                    counted(|| {
                        entry(&bytes);
                    })
                })
                .collect();
            if !calls.iter().all(Call::is_clean) {
                unclean.push(format!("{}/{name}: {calls:?}", target.name));
            }
            replayed += 1;
        }
    }
    assert!(replayed > 0, "no seed was replayed");
    assert!(
        unclean.is_empty(),
        "calls that started a thread, allocated or freed on another thread, or kept or \
         freed more blocks than they allocated, after each seed's first call: {unclean:#?}"
    );
}
