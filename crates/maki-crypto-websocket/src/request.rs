//! Borrowed request serialization into a fixed, owned secret buffer. No
//! request Value tree or owned base64 string is constructed. Library-private
//! serializer/base64 scratch and tungstenite's framing buffers remain outside
//! this owner's zeroization guarantee.

use std::io::{self, Cursor, Write};

use base64::display::Base64Display;
use base64::engine::general_purpose::STANDARD;
use maki_crypto::{CryptoContext, CryptoError, SecretBuffer};
use serde::ser::SerializeSeq;
use serde::{Serialize, Serializer};
use tokio_tungstenite::tungstenite::{Bytes, Message, Utf8Bytes};

// Match the key order of the existing serde_json Value wire representation.
#[derive(Serialize)]
struct Request<'a> {
    format: u32,
    id: u64,
    items: Items<'a>,
    op: &'a str,
    profile: &'a str,
    volume: &'a uuid::Uuid,
}

struct Items<'a>(&'a [(u64, &'a [u8])]);

impl Serialize for Items<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(self.0.len()))?;
        for (unit, data) in self.0 {
            sequence.serialize_element(&Item {
                data: EncodedPayload(data),
                unit: *unit,
            })?;
        }
        sequence.end()
    }
}

#[derive(Serialize)]
struct Item<'a> {
    data: EncodedPayload<'a>,
    unit: u64,
}

struct EncodedPayload<'a>(&'a [u8]);

impl Serialize for EncodedPayload<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        // serde_json streams collect_str directly to its writer; Display's
        // chunked base64 encoder does not construct an owned payload string.
        serializer.collect_str(&Base64Display::new(self.0, &STANDARD))
    }
}

pub(super) struct LengthCounter {
    pub(super) bytes: usize,
    pub(super) limit: usize,
}

impl Write for LengthCounter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let next = self
            .bytes
            .checked_add(bytes.len())
            .filter(|next| *next <= self.limit && *next <= isize::MAX as usize)
            .ok_or_else(|| io::Error::other("request exceeds frame limit"))?;
        self.bytes = next;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(super) fn encode_request(
    id: u64,
    op: &str,
    context: &CryptoContext,
    items: &[(u64, &[u8])],
    max_frame_bytes: usize,
) -> Result<SecretBuffer, CryptoError> {
    let request = Request {
        format: context.format_version,
        id,
        items: Items(items),
        op,
        profile: &context.crypto_compatibility_id,
        volume: &context.volume_uuid,
    };
    // Count with the same serializer before any output allocation. The
    // immutable borrowed request makes both passes deterministic; checked
    // arithmetic, Vec's addressable range, and the frame limit reject
    // impossible capacities before SecretBuffer allocates its storage.
    let mut counter = LengthCounter {
        bytes: 0,
        limit: max_frame_bytes,
    };
    serde_json::to_writer(&mut counter, &request).map_err(|_| {
        CryptoError::NonRetryableRequest(format!("request exceeds frame limit {max_frame_bytes}"))
    })?;
    serialize_fixed(&request, counter.bytes)
}

pub(super) fn serialize_fixed<T: Serialize>(
    value: &T,
    length: usize,
) -> Result<SecretBuffer, CryptoError> {
    // A growing Vec could free old plaintext allocations during reallocation.
    // This initialized, fixed buffer is guarded before its first write and
    // its Cursor refuses to grow, including on a partial serialization error.
    let mut encoded = SecretBuffer::zeroed(length);
    let mut writer = Cursor::new(encoded.expose_mut());
    serde_json::to_writer(&mut writer, value)
        .map_err(|_| CryptoError::NonRetryableRequest("request serialization failed".into()))?;
    if writer.position() != length as u64 {
        return Err(CryptoError::NonRetryableRequest(
            "request serialization length mismatch".into(),
        ));
    }
    Ok(encoded)
}

struct FrameOwner(SecretBuffer);

impl AsRef<[u8]> for FrameOwner {
    fn as_ref(&self) -> &[u8] {
        self.0.expose()
    }
}

pub(super) fn into_message(encoded: SecretBuffer) -> Result<Message, CryptoError> {
    // Bytes retains the owner through queueing, Message clones, and transport
    // handoff; the original allocation is wiped when its last reference dies.
    let bytes = Bytes::from_owner(FrameOwner(encoded));
    let text = Utf8Bytes::try_from(bytes).map_err(|_| {
        CryptoError::NonRetryableRequest("request serialization is not UTF-8".into())
    })?;
    Ok(Message::Text(text))
}
