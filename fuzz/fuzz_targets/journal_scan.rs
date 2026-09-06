#![no_main]
//! Coverage-guided fuzzing of the journal segment scanner. On any input it
//! must terminate with a classification (Clean / TornTail / Corrupt) and
//! never panic, over-read, or loop. The leading bytes seed the base
//! sequence and the durable-length hint the scanner uses to tell durable
//! corruption from a torn tail.

use libfuzzer_sys::fuzz_target;

use maki_format::journal::scan_segment_bounded;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 {
        return;
    }
    let first_sequence = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let knob = data[8];
    let buf = &data[9..];
    let durable_len = if knob & 1 == 0 {
        None
    } else {
        // A durable prefix anywhere in [0, buf.len()].
        Some((knob as usize).wrapping_mul(7) % (buf.len() + 1))
    };
    let _ = scan_segment_bounded(buf, first_sequence, durable_len);
});
