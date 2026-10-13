//! Serialized endpoint budgets for complete control snapshots (BUG-075).
//!
//! The control protocol retains its 64 KiB line bound. Reserve 16 KiB for
//! fixed engine/security/cache fields, their maximum-width numeric values,
//! the bounded volume name and response envelope. Endpoint status rows and
//! the three per-endpoint metric maps share the remaining 48 KiB.

/// Endpoint-dependent part of a complete control response.
pub const CONTROL_ENDPOINT_BUDGET: usize = 48 * 1024;

/// Status row fields plus three map entries, allowing 20-byte u64 values,
/// 24-byte finite float representations, object syntax, and field names.
/// A name can occur four times across these documents; using their combined
/// cost is conservative because status and metrics are separate responses.
const ENDPOINT_FIXED_BYTES: usize = 384;
const NAME_OCCURRENCES: usize = 4;

/// Whether all endpoint names and rows fit the control response allowance.
/// Count JSON escaping without allocating another copy of arbitrary names.
pub fn fits_control_response<'a>(names: impl IntoIterator<Item = &'a str>) -> bool {
    let mut used = 0usize;
    for name in names {
        let mut encoded_name = 2usize; // JSON quotes.
        for byte in name.bytes() {
            let encoded_byte = match byte {
                b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
                0..=0x1f => 6,
                _ => 1,
            };
            let Some(next) = encoded_name.checked_add(encoded_byte) else {
                return false;
            };
            encoded_name = next;
            if encoded_name > CONTROL_ENDPOINT_BUDGET / NAME_OCCURRENCES {
                return false;
            }
        }
        let Some(next) = encoded_name
            .checked_mul(NAME_OCCURRENCES)
            .and_then(|names| names.checked_add(ENDPOINT_FIXED_BYTES))
            .and_then(|endpoint| used.checked_add(endpoint))
        else {
            return false;
        };
        used = next;
        if used > CONTROL_ENDPOINT_BUDGET {
            return false;
        }
    }
    true
}
