//! Audit round 4 (#303 page-unlock): the per-page owner registry must keep
//! every live `SecretBuffer`/`SecretBox` page locked however other owners on
//! neighbouring and shared pages come and go, and must leave nothing locked
//! once every owner is gone. Probes the kernel state (`/proc/self/smaps`
//! VmFlags `lo`, `/proc/self/status` VmLck) rather than the registry.

#![cfg(target_os = "linux")]

use std::sync::{Arc, Barrier};

use maki_crypto::secret::{page_lock_failures, set_page_locking};
use maki_crypto::{SecretBox, SecretBuffer};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

static CHECKED: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

fn page_size() -> usize {
    // SAFETY: sysconf has no pointer arguments.
    unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
}

fn locked_ranges() -> Vec<(usize, usize)> {
    let maps = std::fs::read_to_string("/proc/self/smaps").unwrap();
    let mut out = Vec::new();
    let mut current = None;
    for line in maps.lines() {
        if let Some((start, end)) = line
            .split_whitespace()
            .next()
            .and_then(|s| s.split_once('-'))
            .and_then(|(s, e)| {
                Some((
                    usize::from_str_radix(s, 16).ok()?,
                    usize::from_str_radix(e, 16).ok()?,
                ))
            })
        {
            current = Some((start, end));
        } else if line.starts_with("VmFlags:") {
            if let Some(range) = current.take() {
                if line.split_whitespace().any(|flag| flag == "lo") {
                    out.push(range);
                }
            }
        }
    }
    out
}

fn locked(ranges: &[(usize, usize)], address: usize) -> bool {
    ranges.iter().any(|(s, e)| (*s..*e).contains(&address))
}

fn vm_locked_kib() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmLck:"))
        .map(|v| v.trim().trim_end_matches("kB").trim().parse().unwrap())
        .unwrap()
}

enum Held {
    Buffer(SecretBuffer),
    Boxed(SecretBox<[u8; 700]>),
}

impl Held {
    /// First and last byte of the guarded allocation.
    fn span(&self) -> Option<(usize, usize)> {
        match self {
            Held::Buffer(b) if b.is_page_locked() => {
                let start = b.expose().as_ptr() as usize;
                Some((start, start + b.capacity() - 1))
            }
            Held::Boxed(b) if b.is_page_locked() => {
                let start = (&**b) as *const [u8; 700] as usize;
                Some((start, start + 699))
            }
            _ => None,
        }
    }
}

fn make(rng: &mut StdRng) -> Held {
    let page = page_size();
    match rng.random_range(0..7) {
        0 => Held::Buffer(SecretBuffer::zeroed(rng.random_range(1..3 * page))),
        1 => Held::Buffer(SecretBuffer::from_slice(&vec![
            0x5A;
            rng.random_range(1..200)
        ])),
        2 => {
            let cap = rng.random_range(1..4 * page);
            let mut b = SecretBuffer::with_capacity(cap).unwrap();
            b.try_extend_from_slice(&vec![1; rng.random_range(0..=cap)])
                .unwrap();
            Held::Buffer(b)
        }
        3 => {
            let mut v = Vec::with_capacity(rng.random_range(64..2 * page));
            v.extend_from_slice(&[7; 32]);
            Held::Buffer(SecretBuffer::from_vec(v))
        }
        4 => Held::Boxed(SecretBox::new([3u8; 700])),
        5 => Held::Buffer(SecretBuffer::zeroed(rng.random_range(1..64))),
        _ => Held::Buffer(SecretBuffer::zeroed(page * rng.random_range(1..4))),
    }
}

#[test]
fn live_owners_stay_locked_and_nothing_stays_locked_after_the_last_owner() {
    set_page_locking(true);
    let failures_before = page_lock_failures();
    let baseline = vm_locked_kib();
    const THREADS: usize = 4;
    const ROUNDS: usize = 3;
    let violations = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    for round in 0..ROUNDS {
        let barrier = Arc::new(Barrier::new(THREADS + 1));
        let mut handles = Vec::new();
        for t in 0..THREADS {
            let barrier = barrier.clone();
            let violations = violations.clone();
            handles.push(std::thread::spawn(move || {
                let mut rng = StdRng::seed_from_u64((round * 100 + t) as u64);
                let mut held: Vec<Held> = Vec::new();
                for i in 0..1500 {
                    match rng.random_range(0..10) {
                        0..=4 => held.push(make(&mut rng)),
                        5 | 6 if !held.is_empty() => {
                            let idx = rng.random_range(0..held.len());
                            drop(held.swap_remove(idx));
                        }
                        7 if !held.is_empty() => {
                            let idx = rng.random_range(0..held.len());
                            if let Held::Buffer(b) = held.swap_remove(idx) {
                                let mut v = b.into_vec();
                                v.iter_mut().for_each(|x| *x = 0);
                            }
                        }
                        8 if !held.is_empty() => {
                            let idx = rng.random_range(0..held.len());
                            if let Held::Buffer(b) = &held[idx] {
                                held.push(Held::Buffer(b.duplicate()));
                            }
                        }
                        _ => {}
                    }
                    if held.len() > 48 {
                        held.drain(..16);
                    }
                    // While every other thread churns, a buffer this thread
                    // owns must remain locked from its first to last byte.
                    if i % 97 == 0 && !held.is_empty() {
                        let ranges = locked_ranges();
                        for h in &held {
                            if let Some((first, last)) = h.span() {
                                CHECKED.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                if !locked(&ranges, first) || !locked(&ranges, last) {
                                    violations.lock().unwrap().push(format!(
                                        "round {round} thread {t} iter {i}: live owner \
                                         {first:#x}..={last:#x} not locked"
                                    ));
                                }
                            }
                        }
                    }
                }
                barrier.wait(); // all threads done churning
                barrier.wait(); // main checked the quiescent state
                drop(held);
            }));
        }
        barrier.wait();
        // Quiescent: nothing else mutates locks now.
        barrier.wait();
        for h in handles {
            h.join().unwrap();
        }
        let after = vm_locked_kib();
        if after != baseline {
            violations.lock().unwrap().push(format!(
                "round {round}: VmLck {after} kB after every owner dropped, baseline {baseline} kB"
            ));
        }
    }
    let checked = CHECKED.load(std::sync::atomic::Ordering::Relaxed);
    eprintln!("checked {checked} live spans; baseline VmLck {baseline} kB");
    assert!(checked > 1000, "the probe checked too few live owners");
    // Negative control: the probe sees a page the last owner released.
    let control = SecretBuffer::zeroed(5 * page_size());
    let middle = control.expose().as_ptr() as usize + 2 * page_size();
    assert!(locked(&locked_ranges(), middle));
    let control = control.into_vec();
    assert!(!locked(
        &locked_ranges(),
        control.as_ptr() as usize + 2 * page_size()
    ));
    drop(control);
    assert_eq!(page_lock_failures(), failures_before, "mlock failed");
    let violations = violations.lock().unwrap();
    assert!(
        violations.is_empty(),
        "{:#?}",
        &violations[..violations.len().min(20)]
    );
}
