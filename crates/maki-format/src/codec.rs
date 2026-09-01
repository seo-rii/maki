//! Bounds-checked little-endian byte codec. Reads on malformed input return
//! `FormatError::Truncated`/`Invalid` — never panic, never over-allocate.

use uuid::Uuid;

use crate::error::FormatError;

pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn take(&mut self, n: usize) -> Result<&'a [u8], FormatError> {
        if self.remaining() < n {
            return Err(FormatError::Truncated(format!(
                "need {n} bytes at offset {}, have {}",
                self.pos,
                self.remaining()
            )));
        }
        let out = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    pub fn u8(&mut self) -> Result<u8, FormatError> {
        Ok(self.take(1)?[0])
    }

    pub fn u16(&mut self) -> Result<u16, FormatError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }

    pub fn u32(&mut self) -> Result<u32, FormatError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }

    pub fn u64(&mut self) -> Result<u64, FormatError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }

    pub fn uuid(&mut self) -> Result<Uuid, FormatError> {
        Ok(Uuid::from_bytes(self.take(16)?.try_into().unwrap()))
    }

    /// Length-prefixed (u16) UTF-8 string with an explicit maximum.
    pub fn string(&mut self, max: usize) -> Result<String, FormatError> {
        let len = self.u16()? as usize;
        if len > max {
            return Err(FormatError::Invalid(format!(
                "string length {len} exceeds max {max}"
            )));
        }
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| FormatError::Invalid("string is not UTF-8".to_string()))
    }
}

#[derive(Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn bytes(&mut self, b: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(b);
        self
    }

    pub fn u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }

    pub fn uuid(&mut self, v: &Uuid) -> &mut Self {
        self.bytes(v.as_bytes())
    }

    pub fn string(&mut self, s: &str, max: usize) -> Result<&mut Self, FormatError> {
        if s.len() > max {
            return Err(FormatError::Invalid(format!(
                "string length {} exceeds max {max}",
                s.len()
            )));
        }
        self.u16(s.len() as u16);
        Ok(self.bytes(s.as_bytes()))
    }

    pub fn pad_to(&mut self, len: usize) -> &mut Self {
        if self.buf.len() < len {
            self.buf.resize(len, 0);
        }
        self
    }

    /// Append crc32 of everything written so far.
    pub fn finish_with_crc(mut self) -> Vec<u8> {
        let crc = crc32fast::hash(&self.buf);
        self.buf.extend_from_slice(&crc.to_le_bytes());
        self.buf
    }

    pub fn into_inner(self) -> Vec<u8> {
        self.buf
    }
}

/// Verify a trailing crc32; returns the covered payload.
pub fn strip_verify_crc<'a>(buf: &'a [u8], what: &str) -> Result<&'a [u8], FormatError> {
    if buf.len() < 4 {
        return Err(FormatError::Truncated(format!("{what}: no room for crc")));
    }
    let (payload, crc_bytes) = buf.split_at(buf.len() - 4);
    let expected = u32::from_le_bytes(crc_bytes.try_into().unwrap());
    if crc32fast::hash(payload) != expected {
        return Err(FormatError::BadChecksum(what.to_string()));
    }
    Ok(payload)
}
