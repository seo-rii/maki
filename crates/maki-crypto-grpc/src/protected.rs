//! Provider-owned protobuf items. Public fixture/protocol structs keep their
//! existing API; only the provider's codec uses these allocation owners.
//!
//! Protection belongs on each item: Prost can fail while decoding a child
//! before adding it to a request/response. A parent-only Drop misses that child.
//! Tonic's encoding, decoding and HTTP/TLS buffers remain separate allocations.

use prost::bytes::{Buf, BufMut};
use prost::encoding::{self, DecodeContext, WireType};
use prost::{DecodeError, Message};
use zeroize::Zeroize;

#[derive(Default, PartialEq)]
pub(super) struct WireItem {
    pub(super) unit_index: u64,
    pub(super) data: Vec<u8>,
}

impl Drop for WireItem {
    fn drop(&mut self) {
        // Vec::zeroize also erases initialized data in spare capacity.
        self.data.zeroize();
    }
}

impl std::fmt::Debug for WireItem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WireItem")
            .field("unit_index", &self.unit_index)
            .field("data_len", &self.data.len())
            .field("data", &"<redacted>")
            .finish()
    }
}

impl Message for WireItem {
    fn encode_raw(&self, buf: &mut impl BufMut) {
        if self.unit_index != 0 {
            encoding::uint64::encode(1, &self.unit_index, buf);
        }
        if !self.data.is_empty() {
            encoding::bytes::encode(2, &self.data, buf);
        }
    }

    fn merge_field(
        &mut self,
        tag: u32,
        wire_type: WireType,
        buf: &mut impl Buf,
        ctx: DecodeContext,
    ) -> Result<(), DecodeError> {
        match tag {
            1 => encoding::uint64::merge(wire_type, &mut self.unit_index, buf, ctx),
            2 => {
                // A repeated singular bytes field replaces its prior value.
                // Erase BEFORE validation or growth: a bad replacement also
                // retires the old secret, and realloc must never abandon it.
                self.data.zeroize();
                encoding::check_wire_type(WireType::LengthDelimited, wire_type)?;
                let len = encoding::decode_varint(buf)?;
                if len > buf.remaining() as u64 {
                    return Err(DecodeError::new("buffer underflow"));
                }
                // The comparison bounds the conversion by an existing usize.
                self.data.resize(len as usize, 0);
                // Do not use bytes::merge's intermediate copy_to_bytes: a
                // generic Buf may allocate an unprotected temporary there.
                buf.copy_to_slice(&mut self.data);
                Ok(())
            }
            _ => encoding::skip_field(wire_type, tag, buf, ctx),
        }
    }

    fn encoded_len(&self) -> usize {
        let unit_len = if self.unit_index == 0 {
            0
        } else {
            encoding::uint64::encoded_len(1, &self.unit_index)
        };
        unit_len
            + if self.data.is_empty() {
                0
            } else {
                encoding::bytes::encoded_len(2, &self.data)
            }
    }

    fn clear(&mut self) {
        self.unit_index = 0;
        self.data.zeroize();
    }
}

#[derive(PartialEq, Message)]
pub(super) struct WireRequest {
    #[prost(string, tag = "1")]
    pub(super) volume_id: String,
    #[prost(string, tag = "2")]
    pub(super) compatibility_id: String,
    #[prost(message, repeated, tag = "3")]
    pub(super) items: Vec<WireItem>,
    #[prost(uint32, tag = "4")]
    pub(super) format_version: u32,
}

#[derive(PartialEq, Message)]
pub(super) struct WireResponse {
    #[prost(message, repeated, tag = "1")]
    pub(super) items: Vec<WireItem>,
}
