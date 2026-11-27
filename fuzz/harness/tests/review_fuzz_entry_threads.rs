//! No fuzz entry function starts a thread per input.
//!
//! libFuzzer runs every input of a run in one process, about 10 million of
//! them in each process of a qualification shard, and under
//! AddressSanitizer that process's memory grows with every thread it has
//! started, also once the thread has ended. `nbd_handshake` ran its server
//! side on a thread of its own per input: all eight processes of its 24
//! CPU-hour qualification passed `-rss_limit_mb=2048` after about 10
//! million inputs each, and the inputs libFuzzer wrote as out-of-memory
//! include the empty one. An entry may start a thread on its first input
//! and hand it the later ones.
//!
//! Linux hands out thread ids in increasing order (up to `pid_max`, then
//! from the bottom again), so a call that starts a thread puts at least one
//! id between those of a thread started before it and one started after
//! it. Every committed seed of every target (as `review_fuzz_corpus.rs`
//! replays them) is called with a probe thread before and after each call,
//! and passes at the first call after which the probe's id is the next one
//! after the previous probe's. Other processes on the host take ids too,
//! so a seed fails only when that never happens in [`CALLS`] calls in each
//! of [`ROUNDS`] rounds over the seeds left.
#![cfg(target_os = "linux")]

use std::path::Path;

use maki_fuzz_harness::{seeds, Entry, TARGETS};

/// Calls of a seed in one round, each followed by a probe thread.
const CALLS: usize = 32;

/// Rounds over the seeds that have not passed.
const ROUNDS: usize = 16;

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

/// The id of a thread started now.
fn new_thread_id() -> u64 {
    std::thread::spawn(|| {
        // `<pid>/task/<tid>`
        let link = std::fs::read_link("/proc/thread-self").expect("/proc/thread-self");
        link.file_name()
            .and_then(|name| name.to_str())
            .and_then(|name| name.parse().ok())
            .unwrap_or_else(|| panic!("/proc/thread-self is {}", link.display()))
    })
    .join()
    .expect("the probe thread")
}

/// A seed that has not passed, and the fewest ids a call of it put between
/// two probes.
struct Seed {
    name: String,
    entry: Entry,
    bytes: Vec<u8>,
    fewest: Option<u64>,
}

impl Seed {
    /// Whether one of [`CALLS`] calls put no id between the probes.
    fn passes(&mut self) -> bool {
        let mut before = new_thread_id();
        for _ in 0..CALLS {
            (self.entry)(&self.bytes);
            let after = new_thread_id();
            // `None`: the ids started from the bottom again.
            if let Some(between) = after.checked_sub(before + 1) {
                if between == 0 {
                    return true;
                }
                self.fewest = Some(self.fewest.map_or(between, |fewest| fewest.min(between)));
            }
            before = after;
        }
        false
    }
}

#[test]
fn no_entry_function_starts_a_thread_per_input() {
    let mut left = Vec::new();
    for target in TARGETS {
        let Some(entry) = target.entry else {
            continue;
        };
        for (name, bytes) in seeds_of(target.name) {
            // A thread started on a target's first input only is not one
            // per input.
            entry(&bytes);
            left.push(Seed {
                name: format!("{}/{name}", target.name),
                entry,
                bytes,
                fewest: None,
            });
        }
    }
    assert!(!left.is_empty(), "no seed was replayed");
    // A seed that has not passed is called again in the next round, after
    // every other seed left: what another process does on the host for a
    // while does not fail it.
    for _ in 0..ROUNDS {
        left.retain_mut(|seed| !seed.passes());
    }
    let per_input: Vec<String> = left
        .iter()
        .map(|seed| match seed.fewest {
            Some(fewest) => format!("{}: at least {fewest} per call", seed.name),
            None => format!("{}: the ids started from the bottom again", seed.name),
        })
        .collect();
    assert!(
        per_input.is_empty(),
        "entry functions that start a thread per input: each of {} calls of these seeds \
         put thread ids between the probes before and after it: {per_input:#?}",
        CALLS * ROUNDS
    );
}
