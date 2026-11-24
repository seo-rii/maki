#![no_main]
//! Round-8 audit target (not in the repository): model-based fuzzing of the
//! journal segment scanner. The committed `journal_scan` target feeds raw
//! bytes, so (CRC-32 again) the scanner almost never sees two valid records
//! in a row. Here the input is a recipe: a list of records, each valid or
//! damaged in a chosen way, from which the segment body is assembled with
//! correct checksums. The scanner's answer is then compared with what the
//! recipe says it must be.

use libfuzzer_sys::fuzz_target;

use maki_format::journal::{
    encode_record_parts, scan_segment_bounded, ScanOutcome, RECORD_HEADER_SIZE,
};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Kind {
    Valid,
    /// One payload bit flipped (payload CRC mismatch); needs a payload.
    BadPayload,
    /// One header byte flipped (header CRC mismatch).
    BadHeader,
    /// Valid record whose sequence is not the expected one.
    WrongSequence,
    /// The record is cut short and nothing follows it.
    Truncated,
    /// A run of zero bytes, then nothing.
    Zeros,
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 10 {
        return;
    }
    let first_sequence = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let durable_knob = data[8];
    let tail_knob = data[9];
    let mut recipe = &data[10..];

    let mut body: Vec<u8> = Vec::new();
    // (start offset, kind) of every element, in order.
    let mut elements: Vec<(usize, Kind, usize)> = Vec::new();
    let mut seq = first_sequence;
    let mut valid_prefix_records = 0usize;
    let mut first_bad: Option<(usize, Kind)> = None;
    let mut expected_payloads: Vec<(u64, u64, Vec<u8>)> = Vec::new();

    while recipe.len() >= 4 && elements.len() < 64 {
        let kind_byte = recipe[0];
        let unit = recipe[1] as u64 | ((recipe[2] as u64) << 32);
        let len = (recipe[3] as usize) % 97;
        recipe = &recipe[4..];
        let take = len.min(recipe.len());
        let payload = recipe[..take].to_vec();
        recipe = &recipe[take..];

        let mut kind = match kind_byte % 16 {
            0 => Kind::BadPayload,
            1 => Kind::BadHeader,
            2 => Kind::WrongSequence,
            3 => Kind::Truncated,
            4 => Kind::Zeros,
            _ => Kind::Valid,
        };
        if kind == Kind::BadPayload && payload.is_empty() {
            kind = Kind::Valid;
        }
        let start = body.len();
        match kind {
            Kind::Valid => {
                let Some(next) = seq.checked_add(1) else {
                    break;
                };
                body.extend(encode_record_parts(seq, unit, &payload).unwrap());
                if first_bad.is_none() {
                    valid_prefix_records += 1;
                    expected_payloads.push((seq, unit, payload.clone()));
                }
                seq = next;
            }
            Kind::BadPayload => {
                let mut rec = encode_record_parts(seq, unit, &payload).unwrap();
                let at = RECORD_HEADER_SIZE + (kind_byte as usize >> 4) % payload.len();
                rec[at] ^= 0x10;
                body.extend(rec);
                seq = seq.wrapping_add(1);
            }
            Kind::BadHeader => {
                let mut rec = encode_record_parts(seq, unit, &payload).unwrap();
                rec[4 + (kind_byte as usize >> 4) % 24] ^= 0x01;
                body.extend(rec);
                seq = seq.wrapping_add(1);
            }
            Kind::WrongSequence => {
                let wrong = seq.wrapping_add(1 + (kind_byte as u64 >> 4));
                body.extend(encode_record_parts(wrong, unit, &payload).unwrap());
            }
            Kind::Truncated => {
                let rec = encode_record_parts(seq, unit, &payload).unwrap();
                let keep = 1 + (kind_byte as usize >> 4) % (rec.len() - 1);
                body.extend(&rec[..keep]);
            }
            Kind::Zeros => {
                body.extend(std::iter::repeat(0u8).take(1 + len));
            }
        }
        elements.push((start, kind, body.len()));
        if kind != Kind::Valid && first_bad.is_none() {
            first_bad = Some((start, kind));
        }
        if matches!(kind, Kind::Truncated | Kind::Zeros) {
            break;
        }
    }
    // Optional zero tail after the last element (preallocation).
    if tail_knob & 1 == 1 && !matches!(elements.last(), Some((_, Kind::Truncated, _))) {
        body.extend(std::iter::repeat(0u8).take((tail_knob as usize >> 1) + 1));
    }

    let valid_end = first_bad.map(|(at, _)| at).unwrap_or_else(|| {
        elements
            .iter()
            .filter(|(_, k, _)| *k == Kind::Valid)
            .map(|(_, _, end)| *end)
            .last()
            .unwrap_or(0)
    });

    for durable_len in [
        None,
        Some(0usize),
        Some(valid_end),
        Some(body.len()),
        Some((durable_knob as usize).wrapping_mul(13) % (body.len() + 1)),
    ] {
        let (records, outcome) = scan_segment_bounded(&body, first_sequence, durable_len);

        // 1. The records are exactly the valid prefix the recipe built.
        assert_eq!(
            records.len(),
            valid_prefix_records,
            "durable_len {durable_len:?}: scanner returned {} records, recipe has {} valid ones \
             before the first damage; outcome {outcome:?}",
            records.len(),
            valid_prefix_records
        );
        for (rec, (s, u, p)) in records.iter().zip(&expected_payloads) {
            assert!(rec.sequence == *s && rec.unit_index == *u && rec.payload == *p);
        }

        // 2. The classification point is the first damaged element.
        match (&outcome, first_bad) {
            (ScanOutcome::Clean, None) => {}
            (ScanOutcome::Clean, Some((at, Kind::Zeros))) => {
                // Zeros to the end of the buffer are a clean tail, unless
                // inside the durable prefix.
                assert!(!durable_len.is_some_and(|d| at < d));
            }
            (ScanOutcome::TornTail { at }, Some((bad, kind))) => {
                assert_eq!(*at, bad, "torn tail reported at the wrong offset");
                assert_ne!(kind, Kind::WrongSequence, "a sequence gap is never a torn tail");
                // Never a torn tail inside the proven-durable prefix.
                assert!(
                    !durable_len.is_some_and(|d| bad < d),
                    "damage at {bad} inside durable prefix {durable_len:?} classified as torn"
                );
            }
            (ScanOutcome::Corrupt { at, .. }, Some((bad, _))) => {
                assert_eq!(*at, bad, "corruption reported at the wrong offset");
            }
            (ScanOutcome::Corrupt { at, .. }, None) => {
                // Only "segment ends before durable prefix" or a zero tail
                // inside the durable prefix can be corrupt with no damage.
                assert!(durable_len.is_some_and(|d| *at < d), "corrupt without damage");
            }
            (other, None) => panic!("no damage in the recipe but outcome {other:?}"),
            (other, Some(bad)) => panic!("outcome {other:?} for first damage {bad:?}"),
        }

        // 3. With the durable prefix known to end at the valid prefix, damage
        //    behind it must never be reported as corruption unless it is a
        //    sequence gap or an oversized length (not generated here).
        if durable_len == Some(valid_end) {
            if let (ScanOutcome::Corrupt { .. }, Some((_, kind))) = (&outcome, first_bad) {
                assert_eq!(
                    kind,
                    Kind::WrongSequence,
                    "unsynced damage after the durable prefix classified as corruption"
                );
            }
        }

        // 4. Truncating at a torn tail leaves a clean segment with the same
        //    records (recovery relies on this: S-05).
        if let ScanOutcome::TornTail { at } = outcome {
            let (again, clean) = scan_segment_bounded(&body[..at], first_sequence, durable_len.map(|d| d.min(at)));
            assert_eq!(clean, ScanOutcome::Clean);
            assert_eq!(again.len(), records.len());
        }
    }
});
