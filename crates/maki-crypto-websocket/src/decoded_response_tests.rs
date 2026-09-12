//! MAKI-015 (partial): decoded response allocations must be wiped on every
//! error path. JSON/base64 strings and transport-private buffers are outside
//! this regression's scope.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use super::*;

const PAYLOAD_LEN: usize = 257;
const OLD_DECODE_CAPACITY: usize = 258;
const FILL: u8 = 0xA5;

#[derive(Clone, Copy, Default, Debug)]
struct Inspection {
    address: usize,
    allocated: usize,
    freed: usize,
    all_zero: bool,
    plaintext_prefix: bool,
}

thread_local! {
    static INSPECTION: Cell<Option<Inspection>> = const { Cell::new(None) };
}

struct InspectDecodedAllocation;

// SAFETY: all operations delegate to System. Only alloc_zeroed allocations of
// the selected decoder sizes are registered, so every inspected byte was
// initialized. Inspection occurs before System.dealloc, never after freeing.
// The observer is thread-local and performs no allocation itself.
unsafe impl GlobalAlloc for InspectDecodedAllocation {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() && matches!(layout.size(), PAYLOAD_LEN | OLD_DECODE_CAPACITY) {
            let _ = INSPECTION.try_with(|cell| {
                if let Some(mut inspection) = cell.get() {
                    inspection.allocated += 1;
                    inspection.address = pointer as usize;
                    cell.set(Some(inspection));
                }
            });
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        let _ = INSPECTION.try_with(|cell| {
            if let Some(mut inspection) = cell.get() {
                if inspection.address == pointer as usize {
                    // SAFETY: this exact allocation came from alloc_zeroed,
                    // remains live, and layout describes its entire capacity.
                    let bytes = unsafe { std::slice::from_raw_parts(pointer, layout.size()) };
                    inspection.all_zero = bytes.iter().all(|byte| *byte == 0);
                    inspection.plaintext_prefix = bytes[..64].iter().all(|byte| *byte == FILL);
                    inspection.freed += 1;
                    inspection.address = 0;
                    cell.set(Some(inspection));
                }
            }
        });
        unsafe { System.dealloc(pointer, layout) }
    }
}

#[global_allocator]
static ALLOCATOR: InspectDecodedAllocation = InspectDecodedAllocation;

struct Watch;

impl Watch {
    fn start() -> Self {
        INSPECTION.with(|cell| {
            assert!(cell.replace(Some(Inspection::default())).is_none());
        });
        Self
    }

    fn finish(self) -> Inspection {
        INSPECTION.with(|cell| cell.replace(None).unwrap())
    }
}

impl Drop for Watch {
    fn drop(&mut self) {
        INSPECTION.with(|cell| cell.set(None));
    }
}

fn provider() -> WsCryptoProvider {
    WsCryptoProvider::new(WsProviderSpec {
        url: "ws://unused.invalid/".into(),
        capabilities: CryptoCapabilities {
            provider_id: "decoded-response-test".into(),
            crypto_compatibility_id: "decoded-response-test".into(),
            supported_plaintext_sizes: vec![PAYLOAD_LEN as u32],
            max_ciphertext_size: PAYLOAD_LEN as u32,
            stateless: true,
            retry_safe: true,
            batch: maki_crypto::BatchCapability {
                supported: true,
                max_items: 8,
                max_bytes: 4096,
            },
            integrity: maki_crypto::Capability::Absent,
            context_binding: maki_crypto::Capability::Absent,
            replay_protection: maki_crypto::Capability::Absent,
        },
        timeout: Duration::from_secs(1),
        max_frame_bytes: 4096,
    })
}

fn assert_released_and_wiped(inspection: Inspection) {
    assert_eq!(
        inspection.allocated, 1,
        "decoder allocation was not observed"
    );
    assert_eq!(inspection.freed, 1, "decoder allocation was not released");
    assert_eq!(inspection.address, 0);
    assert!(
        inspection.all_zero,
        "decoded plaintext survived: {inspection:?}"
    );
}

#[test]
fn later_item_failure_wipes_previously_decoded_plaintext() {
    let provider = provider();
    let first = b64(&[FILL; PAYLOAD_LEN]);
    for later in [
        json!({"unit": 99, "data": "AA=="}),
        json!({"unit": 2}),
        json!({"unit": 2, "data": "!"}),
    ] {
        let response = json!({"items": [
            {"unit": 1, "data": first},
            later,
        ]});
        let watch = Watch::start();
        let result = provider.parse_response(&response, &[(1, &[]), (2, &[])]);
        let inspection = watch.finish();
        assert!(matches!(result, Err(CryptoError::Contract(_))));
        assert_released_and_wiped(inspection);
    }
}

#[test]
fn invalid_base64_wipes_bytes_decoded_before_the_error() {
    let provider = provider();
    let mut encoded = b64(&[FILL; PAYLOAD_LEN]).into_bytes();
    let invalid = encoded.len() - 12;
    encoded[invalid] = b'!';
    let encoded = String::from_utf8(encoded).unwrap();
    // Establish that this malformed input actually emits plaintext before
    // the pinned decoder detects the late invalid symbol.
    let mut partial = [0; OLD_DECODE_CAPACITY];
    assert!(base64::engine::general_purpose::STANDARD
        .decode_slice(&encoded, &mut partial)
        .is_err());
    assert_eq!(&partial[..64], &[FILL; 64]);
    let response = json!({"items": [{"unit": 1, "data": encoded}]});
    let watch = Watch::start();
    let result = provider.parse_response(&response, &[(1, &[])]);
    let inspection = watch.finish();
    assert!(matches!(result, Err(CryptoError::Contract(_))));
    assert_released_and_wiped(inspection);
}

// These byte assertions work before and after the raw-output API is guarded,
// keeping the regression runnable against the original implementation.
trait PayloadBytes {
    fn bytes(&self) -> &[u8];
}

impl PayloadBytes for Vec<u8> {
    fn bytes(&self) -> &[u8] {
        self
    }
}

impl PayloadBytes for SecretBuffer {
    fn bytes(&self) -> &[u8] {
        self.expose()
    }
}

#[test]
fn valid_standard_padding_preserves_exact_payload_bytes_and_lengths() {
    let provider = provider();
    for len in [0, 1, 2, 3, 4, 63, 64, 255, 256, 257, 258] {
        let expected: Vec<u8> = (0..len).map(|index| index as u8).collect();
        let response = json!({"items": [{"unit": 1, "data": b64(&expected)}]});
        let result = provider.parse_response(&response, &[(1, &[])]).unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].bytes(), expected, "decoded length {len}");
    }
}

#[test]
fn invalid_standard_alphabet_padding_and_trailing_bits_still_fail() {
    let provider = provider();
    for encoded in [
        "=", "====", "AA=", "A===", "AA==AA==", "AA====", "AA======", "YQ", "YWI", "YQ==\n",
        "YQ-_", "YR==", "YWJ=", "💥",
    ] {
        assert!(base64::engine::general_purpose::STANDARD
            .decode(encoded)
            .is_err());
        let response = json!({"items": [{"unit": 1, "data": encoded}]});
        assert!(
            matches!(
                provider.parse_response(&response, &[(1, &[])]),
                Err(CryptoError::Contract(_))
            ),
            "invalid STANDARD input was accepted: {encoded:?}"
        );
    }
}
