//! Round-2 audit: the patched serde_json `parse_line_col` indexes a
//! `GuardedString` whose `Deref` re-validates the whole message as UTF-8 on
//! every index. Upstream indexes a `String` in O(1), so an error message whose
//! last " at line " is followed by many digits costs O(len * digits) instead
//! of O(len). Messages embed untrusted input (unknown field names, wrong-type
//! string values), so a peer controls both.
use std::time::{Duration, Instant};

use maki_backing::remote_witness::Request;

fn crafted(len: usize) -> Vec<u8> {
    // A witness operation whose `operation_id` is a string instead of the
    // expected byte array: serde reports `invalid type: string "...", expected
    // ...`, embedding the whole string in the custom error message.
    let digits = len - 64;
    format!("{{\"operation_id\":\"x at line {}\"}}", "0".repeat(digits)).into_bytes()
}

fn control(len: usize) -> Vec<u8> {
    let filler = len - 64;
    format!("{{\"operation_id\":\"x at line {}\"}}", "y".repeat(filler)).into_bytes()
}

fn time(input: &[u8]) -> Duration {
    let start = Instant::now();
    let error = serde_json::from_slice::<Request>(input).unwrap_err();
    let elapsed = start.elapsed();
    assert!(error.to_string().starts_with("invalid type: string"));
    elapsed
}

#[test]
fn audit2_error_position_parse_is_quadratic_in_message_digits() {
    let mut report = Vec::new();
    let mut crafted_times = Vec::new();
    for len in [8 * 1024, 16 * 1024, 32 * 1024, 64 * 1024 - 16] {
        let slow = time(&crafted(len));
        let fast = time(&control(len));
        report.push(format!(
            "frame {len} B: digits {slow:?}, same-size control {fast:?} ({:.0}x)",
            slow.as_secs_f64() / fast.as_secs_f64().max(1e-9)
        ));
        crafted_times.push(slow);
    }
    println!("{}", report.join("\n"));
    // 8x the input should cost ~8x for a linear parser; quadratic gives ~64x.
    let ratio = crafted_times[3].as_secs_f64() / crafted_times[0].as_secs_f64();
    println!("8x frame size -> {ratio:.1}x time");
    assert!(
        ratio < 20.0,
        "error construction is super-linear in the attacker-controlled message: {ratio:.1}x"
    );
}
