use core::ops::{Deref, DerefMut, Range};
use zeroize::Zeroize;

use crate::enums::{ContentType, ProtocolVersion};
use crate::error::{Error, PeerMisbehaved};
use crate::msgs::fragmenter::MAX_FRAGMENT_LEN;

/// A TLS frame, named TLSPlaintext in the standard.
///
/// This inbound type borrows its encrypted payload from a buffer elsewhere.
/// It is used for joining and is consumed by decryption.
pub struct InboundOpaqueMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: BorrowedPayload<'a>,
}

impl<'a> InboundOpaqueMessage<'a> {
    /// Construct a new `InboundOpaqueMessage` from constituent fields.
    ///
    /// `payload` is borrowed.
    pub fn new(typ: ContentType, version: ProtocolVersion, payload: &'a mut [u8]) -> Self {
        Self {
            typ,
            version,
            payload: BorrowedPayload(payload),
        }
    }

    /// Force conversion into a plaintext message.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `InboundOpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message(self) -> InboundPlainMessage<'a> {
        InboundPlainMessage {
            typ: self.typ,
            version: self.version,
            payload: self.payload.into_inner(),
        }
    }

    /// Force conversion into a plaintext message.
    ///
    /// `range` restricts the resulting message: this function panics if it is out of range for
    /// the underlying message payload.
    ///
    /// This should only be used for messages that are known to be in plaintext. Otherwise, the
    /// `InboundOpaqueMessage` should be decrypted into a `PlainMessage` using a `MessageDecrypter`.
    pub fn into_plain_message_range(self, range: Range<usize>) -> InboundPlainMessage<'a> {
        // Validate while the drop guard still owns the whole record. Invalid
        // ranges retain indexing's panic behavior and wipe during unwinding.
        assert!(range.start <= range.end && range.end <= self.payload.len());
        let (prefix, remaining) = self
            .payload
            .into_inner()
            .split_at_mut(range.start);
        let (payload, suffix) = remaining.split_at_mut(range.len());
        prefix.zeroize();
        suffix.zeroize();
        InboundPlainMessage {
            typ: self.typ,
            version: self.version,
            payload,
        }
    }

    /// For TLS1.3 (only), checks the length msg.payload is valid and removes the padding.
    ///
    /// Returns an error if the message (pre-unpadding) is too long, or the padding is invalid,
    /// or the message (post-unpadding) is too long.
    pub fn into_tls13_unpadded_message(mut self) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut self.payload;

        if payload.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.typ = unpad_tls13_payload(payload);
        if self.typ == ContentType::Unknown(0) {
            return Err(PeerMisbehaved::IllegalTlsInnerPlaintext.into());
        }

        if payload.len() > MAX_FRAGMENT_LEN {
            return Err(Error::PeerSentOversizedRecord);
        }

        self.version = ProtocolVersion::TLSv1_3;
        Ok(self.into_plain_message())
    }
}

pub struct BorrowedPayload<'a>(&'a mut [u8]);

impl Drop for BorrowedPayload<'_> {
    fn drop(&mut self) {
        // AEAD failures may already have decrypted part of this borrowed
        // record. A successful plaintext transfer empties this guard first.
        self.0.zeroize();
    }
}

impl Deref for BorrowedPayload<'_> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.0
    }
}

impl DerefMut for BorrowedPayload<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0
    }
}

impl<'a> BorrowedPayload<'a> {
    pub fn truncate(&mut self, len: usize) {
        if len >= self.len() {
            return;
        }

        let (remaining, removed) = core::mem::take(&mut self.0).split_at_mut(len);
        removed.zeroize();
        self.0 = remaining;
    }

    pub(crate) fn into_inner(mut self) -> &'a mut [u8] {
        core::mem::take(&mut self.0)
    }

    pub(crate) fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }

        let len = self.len();
        let last = self[len - 1];
        self.truncate(len - 1);
        Some(last)
    }
}

/// A TLS frame, named `TLSPlaintext` in the standard.
///
/// This inbound type borrows its decrypted payload from the original buffer.
/// It results from decryption.
#[derive(Debug)]
pub struct InboundPlainMessage<'a> {
    pub typ: ContentType,
    pub version: ProtocolVersion,
    pub payload: &'a [u8],
}

impl InboundPlainMessage<'_> {
    /// Returns true if the payload is a CCS message.
    ///
    /// We passthrough ChangeCipherSpec messages in the deframer without decrypting them.
    /// Note: this is prior to the record layer, so is unencrypted. See
    /// third paragraph of section 5 in RFC8446.
    pub(crate) fn is_valid_ccs(&self) -> bool {
        self.typ == ContentType::ChangeCipherSpec && self.payload == [0x01]
    }
}

/// Decode a TLS1.3 `TLSInnerPlaintext` encoding.
///
/// `p` is a message payload, immediately post-decryption.  This function
/// removes zero padding bytes, until a non-zero byte is encountered which is
/// the content type, which is returned.  See RFC8446 s5.2.
///
/// ContentType(0) is returned if the message payload is empty or all zeroes.
fn unpad_tls13_payload(p: &mut BorrowedPayload<'_>) -> ContentType {
    loop {
        match p.pop() {
            Some(0) => {}
            Some(content_type) => return ContentType::from(content_type),
            None => return ContentType::Unknown(0),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod maki_erasure_tests {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    use super::*;

    #[test]
    fn maki_inbound_reversed_range_panics_and_erases_plaintext() {
        let mut storage = *b"secret plaintext";
        let result = catch_unwind(AssertUnwindSafe(|| {
            let message = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut storage,
            );
            let _ = message.into_plain_message_range(5..3);
        }));
        assert!(
            result.is_err(),
            "reversed range must retain indexing panic behavior"
        );
        assert!(storage.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maki_inbound_out_of_bounds_range_panics_and_erases_plaintext() {
        let mut storage = *b"secret plaintext";
        let result = catch_unwind(AssertUnwindSafe(|| {
            let message = InboundOpaqueMessage::new(
                ContentType::ApplicationData,
                ProtocolVersion::TLSv1_2,
                &mut storage,
            );
            let _ = message.into_plain_message_range(5..99);
        }));
        assert!(result.is_err());
        assert!(storage.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maki_decryption_error_erases_in_place_plaintext_immediately() {
        let mut storage = *b"partially decrypted plaintext";
        let message = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut storage,
        );
        let decrypt =
            |_message: InboundOpaqueMessage<'_>| -> Result<(), Error> { Err(Error::DecryptError) };
        assert!(decrypt(message).is_err());
        assert!(storage.iter().all(|byte| *byte == 0));
    }

    #[test]
    fn maki_inbound_plaintext_truncation_erases_removed_suffix() {
        let mut storage = *b"secret obsolete";
        let mut payload = BorrowedPayload(&mut storage);
        payload.truncate(6);
        let remaining = payload.into_inner();
        assert_eq!(remaining, b"secret");
        assert_eq!(&storage[6..], &[0; 9]);
    }

    #[test]
    fn maki_inbound_plaintext_range_erases_bytes_outside_transferred_slice() {
        let mut storage = *b"prefixsecretobsolete";
        let message = InboundOpaqueMessage::new(
            ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut storage,
        )
        .into_plain_message_range(6..12);
        assert_eq!(message.payload, b"secret");
        assert_eq!(&storage[..6], &[0; 6]);
        assert_eq!(&storage[12..], &[0; 8]);
    }
}
