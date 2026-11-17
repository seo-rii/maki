//! audit2 (decoder-fuzz): structure-aware mutation of control-socket
//! protocol lines, both directions.
//!
//! * `serve_connection` gets mutated request lines (valid commands with
//!   odd sections/payloads, JSON-level mutations, byte-level mutations,
//!   invalid UTF-8, deep nesting, near/over-limit lines). Properties: no
//!   panic; exactly one response per complete in-limit line, each a JSON
//!   object with a boolean `ok` and at most MAX_LINE bytes; an over-limit
//!   line ends the session with `LineTooLong`; bounded peak allocation on
//!   the (single) runtime thread.
//! * `read_response` gets random server lines: never panics, bounded.
//!
//! maki-control has no `rand` dev-dependency; SplitMix64 keeps it seeded.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::sync::Arc;

use async_trait::async_trait;
use maki_control::protocol::{read_response, ProtocolError, MAX_LINE};
use maki_control::server::{serve_connection, ControlBackend, ControlLimits};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

// ---------------------------------------------------------------- allocator

struct Counting;
thread_local! {
    static LIVE: Cell<isize> = const { Cell::new(0) };
    static PEAK: Cell<isize> = const { Cell::new(0) };
}
fn note_alloc(size: usize) {
    let _ = LIVE.try_with(|live| {
        let now = live.get() + size as isize;
        live.set(now);
        let _ = PEAK.try_with(|peak| {
            if now > peak.get() {
                peak.set(now)
            }
        });
    });
}
fn note_free(size: usize) {
    let _ = LIVE.try_with(|live| live.set(live.get() - size as isize));
}
unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc(layout) }
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        note_alloc(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        note_free(layout.size());
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        note_free(layout.size());
        note_alloc(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}
#[global_allocator]
static GLOBAL: Counting = Counting;

fn reset_peak() -> isize {
    let start = LIVE.with(|l| l.get());
    PEAK.with(|p| p.set(start));
    start
}
fn peak_since(start: isize) -> usize {
    (PEAK.with(|p| p.get()) - start).max(0) as usize
}

struct Prng(u64);
impl Prng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn chance(&mut self, percent: u64) -> bool {
        self.below(100) < percent
    }
}

/// A backend that echoes what it was given, as a careless daemon might.
struct Echo;

#[async_trait]
impl ControlBackend for Echo {
    async fn status(&self) -> Value {
        json!({"state": "running"})
    }
    async fn metrics(&self) -> Value {
        json!({"reads": 1})
    }
    async fn checkpoint(&self) -> Result<u64, String> {
        Ok(7)
    }
    async fn drain(&self) -> Result<u64, String> {
        Err("drain refused".into())
    }
    async fn reload(&self, section: &str, payload: &Value) -> Result<(), String> {
        Err(format!("cannot reload {section:?} with {payload}"))
    }
}

fn odd_string(rng: &mut Prng) -> String {
    match rng.below(9) {
        0 => String::new(),
        1 => "status".into(),
        2 => "attach".into(),
        3 => "\u{0001}".repeat(rng.below(12_000) as usize),
        4 => "é".repeat(rng.below(20_000) as usize),
        5 => "\"\\".repeat(rng.below(16_000) as usize),
        6 => "𝄞".repeat(rng.below(100) as usize),
        7 => "x".repeat(rng.below(70_000) as usize),
        _ => format!("cmd{}", rng.next()),
    }
}

fn odd_value(rng: &mut Prng) -> Value {
    match rng.below(10) {
        0 => Value::Null,
        1 => json!(odd_string(rng)),
        2 => json!(u64::MAX),
        3 => json!(-1e308),
        4 => {
            let mut v = json!(0);
            for _ in 0..rng.below(126) {
                v = json!([v]);
            }
            v
        }
        5 => json!(vec![0; rng.below(20_000) as usize]),
        6 => json!({"cache": {"max_bytes": u64::MAX, "ttl_ms": -1}}),
        7 => json!([odd_string(rng)]),
        _ => json!({"k": rng.next()}),
    }
}

fn request_line(rng: &mut Prng) -> Vec<u8> {
    let commands = [
        "status", "metrics", "checkpoint", "drain", "reload", "attach", "grow", "lvm", "",
    ];
    let mut v = json!({"command": commands[rng.below(commands.len() as u64) as usize]});
    if rng.chance(50) {
        v["section"] = json!(odd_string(rng));
    }
    if rng.chance(50) {
        v["payload"] = odd_value(rng);
    }
    match rng.below(10) {
        0 => v["command"] = odd_value(rng),
        1 => v["section"] = odd_value(rng),
        2 => v["extra"] = odd_value(rng),
        3 => v = odd_value(rng),
        4 => v["command"] = json!(odd_string(rng)),
        _ => {}
    }
    let mut bytes = serde_json::to_vec(&v).unwrap();
    match rng.below(10) {
        0 if !bytes.is_empty() => {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes[at] = b"{}[],:\"0123456789\\\xff\xc3\x00"[rng.below(20) as usize];
        }
        1 if !bytes.is_empty() => {
            let at = rng.below(bytes.len() as u64) as usize;
            bytes.truncate(at);
        }
        2 => {
            // Near the limit: pad inside a string.
            let pad = MAX_LINE.saturating_sub(bytes.len() + 16) + rng.below(32) as usize;
            bytes = serde_json::to_vec(&json!({"command": "x".repeat(pad)})).unwrap();
        }
        3 => bytes.insert(0, b' '),
        _ => {}
    }
    // The newline is the frame boundary; never put one inside a request.
    bytes.retain(|b| *b != b'\n');
    bytes
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

#[test]
fn serve_connection_survives_mutated_request_lines() {
    let seed = 0xC0A7_0001;
    let mut rng = Prng(seed);
    let rt = runtime();
    let mut failures: Vec<String> = Vec::new();
    let (mut lines_total, mut over_limit, mut answered) = (0u64, 0u64, 0u64);
    let mut max_peak = 0usize;
    let sessions = 300;
    for session in 0..sessions {
        let lines: Vec<Vec<u8>> = (0..rng.below(20) + 1).map(|_| request_line(&mut rng)).collect();
        let end_without_newline = rng.chance(20);
        let result = rt.block_on(async {
            let (client, server) = tokio::io::duplex(1 << 20);
            let start = reset_peak();
            let task = tokio::spawn(serve_connection(server, Arc::new(Echo), ControlLimits::default()));
            let (mut rd, mut wr) = tokio::io::split(client);
            let writer = async {
                for (i, line) in lines.iter().enumerate() {
                    wr.write_all(line).await?;
                    if !(end_without_newline && i + 1 == lines.len()) {
                        wr.write_all(b"\n").await?;
                    }
                }
                wr.shutdown().await
            };
            let reader = async {
                let mut all = Vec::new();
                rd.read_to_end(&mut all).await.map(|_| all)
            };
            let (w, r) = tokio::join!(writer, reader);
            let served = task.await;
            (w, r, served, peak_since(start))
        });
        let (_w, r, served, peak) = result;
        max_peak = max_peak.max(peak);
        if peak > 8 << 20 {
            failures.push(format!("session {session}: peak allocation {peak}"));
        }
        let served = match served {
            Err(e) => {
                failures.push(format!("session {session}: serve_connection panicked: {e}"));
                continue;
            }
            Ok(s) => s,
        };
        let output = r.unwrap_or_default();
        // Expected: one response per line until the first over-limit line.
        let mut expected = 0usize;
        let mut hit_limit = false;
        for line in &lines {
            lines_total += 1;
            if line.len() > MAX_LINE {
                over_limit += 1;
                hit_limit = true;
                break;
            }
            expected += 1;
        }
        let responses: Vec<&[u8]> = output.split(|b| *b == b'\n').filter(|l| !l.is_empty()).collect();
        answered += responses.len() as u64;
        // An empty final line without newline is "Closed", not a request.
        let expected = if !hit_limit && end_without_newline && lines.last().is_some_and(|l| l.is_empty()) {
            expected - 1
        } else {
            expected
        };
        let blank_lines = lines.iter().take(expected).filter(|l| l.is_empty()).count();
        if responses.len() != expected && responses.len() + blank_lines != expected {
            failures.push(format!(
                "session {session}: {} responses for {expected} in-limit lines (limit hit: {hit_limit}, result {served:?})",
                responses.len()
            ));
        }
        for resp in &responses {
            if resp.len() > MAX_LINE {
                failures.push(format!("session {session}: response of {} bytes", resp.len()));
            }
            match serde_json::from_slice::<Value>(resp) {
                Ok(v) if v.get("ok").is_some_and(Value::is_boolean) => {}
                Ok(v) => failures.push(format!("session {session}: response without ok: {}", &v.to_string()[..80.min(v.to_string().len())])),
                Err(e) => failures.push(format!("session {session}: response not JSON: {e}")),
            }
        }
        match (&served, hit_limit) {
            (Err(ProtocolError::LineTooLong), true) | (Ok(()), false) => {}
            (other, _) => failures.push(format!("session {session}: ended with {other:?} (limit hit {hit_limit})")),
        }
    }
    eprintln!(
        "[audit2 control] server: seed {seed:#x} {sessions} sessions, {lines_total} lines \
         ({over_limit} over the limit), {answered} responses, max peak {max_peak} bytes"
    );
    for f in failures.iter().take(10) {
        eprintln!("[audit2 control]   {f}");
    }
    assert!(failures.is_empty(), "{} failures", failures.len());
}

#[test]
fn read_response_survives_mutated_server_lines() {
    let seed = 0xC0A7_0002;
    let mut rng = Prng(seed);
    let rt = runtime();
    let mut panics = 0;
    let mut max_peak = 0usize;
    let mut parsed = 0;
    for _ in 0..4000 {
        let mut line = request_line(&mut rng);
        if rng.chance(30) {
            line = (0..rng.below(300)).map(|_| rng.next() as u8).filter(|b| *b != b'\n').collect();
        }
        let terminate = rng.chance(80);
        let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async {
                let (mut client, mut server) = tokio::io::duplex(1 << 20);
                let start = reset_peak();
                server.write_all(&line).await.unwrap();
                if terminate {
                    server.write_all(b"\n").await.unwrap();
                }
                drop(server);
                let result = read_response(&mut client).await;
                (result.is_ok(), peak_since(start))
            })
        }));
        match r {
            Err(_) => panics += 1,
            Ok((ok, peak)) => {
                if ok {
                    parsed += 1;
                }
                max_peak = max_peak.max(peak);
            }
        }
    }
    eprintln!(
        "[audit2 control] client: seed {seed:#x} 4000 lines, {parsed} parsed, max peak {max_peak} bytes"
    );
    assert_eq!(panics, 0);
    assert!(max_peak < 8 << 20, "read_response peak {max_peak}");
}
