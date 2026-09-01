//! Ciphertext slot header (SPEC §14). Fixed 64 bytes, CRC-protected.

use crate::codec::{Reader, Writer};
use crate::error::FormatError;

pub const SLOT_HEADER_SIZE: u32 = crate::geometry::SLOT_HEADER_SIZE;
pub const SLOT_MAGIC: &[u8; 8] = b"MAKISLT1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotHeader {
    pub unit_index: u64,
    pub write_sequence: u64,
    pub ciphertext_len: u32,
    pub flags: u32,
    pub ciphertext_crc: u32,
}

impl SlotHeader {
    pub fn encode(&self) -> [u8; SLOT_HEADER_SIZE as usize] {
        let mut w = Writer::new();
        w.bytes(SLOT_MAGIC)
            .u64(self.unit_index)
            .u64(self.write_sequence)
            .u32(self.ciphertext_len)
            .u32(self.flags)
            .u32(self.ciphertext_crc)
            .bytes(&[0u8; 24]); // reserved
        let out = w.finish_with_crc();
        out.try_into().expect("slot header is 64 bytes")
    }

    pub fn decode(data: &[u8]) -> Result<Self, FormatError> {
        if data.len() < SLOT_HEADER_SIZE as usize {
            return Err(FormatError::Truncated(format!(
                "slot header: {} < {SLOT_HEADER_SIZE}",
                data.len()
            )));
        }
        let data = &data[..SLOT_HEADER_SIZE as usize];
        if &data[0..8] != SLOT_MAGIC {
            return Err(FormatError::BadMagic("slot header".to_string()));
        }
        let payload = crate::codec::strip_verify_crc(data, "slot header")?;
        let mut r = Reader::new(payload);
        let _magic = r.take(8)?;
        let unit_index = r.u64()?;
        let write_sequence = r.u64()?;
        let ciphertext_len = r.u32()?;
        let flags = r.u32()?;
        let ciphertext_crc = r.u32()?;
        Ok(Self {
            unit_index,
            write_sequence,
            ciphertext_len,
            flags,
            ciphertext_crc,
        })
    }
}
