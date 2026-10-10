//! Maki's parser-private heap owners. Never grow a live secret Vec in place.

use alloc::vec::Vec;
use core::fmt::{self, Display, Write};
use core::mem;
use core::ops::Deref;
use core::str;
use zeroize::Zeroize;

#[cfg(feature = "raw_value")]
use crate::error::Error;
#[cfg(feature = "raw_value")]
use alloc::boxed::Box;
#[cfg(feature = "raw_value")]
use alloc::string::String;
#[cfg(feature = "raw_value")]
use serde::de::{self, DeserializeSeed, EnumAccess, IntoDeserializer, VariantAccess, Visitor};
#[cfg(feature = "raw_value")]
use serde::forward_to_deserialize_any;

// Public only because the sealed Read trait names this type in hidden methods.
// Its buffer is deliberately never exposed as &mut Vec.
#[doc(hidden)]
pub struct Scratch {
    bytes: Vec<u8>,
}

impl Scratch {
    pub(crate) fn new() -> Self {
        Scratch { bytes: Vec::new() }
    }

    pub(crate) fn reserve(&mut self, additional: usize) {
        let required = self
            .bytes
            .len()
            .checked_add(additional)
            .expect("capacity overflow");
        if required <= self.bytes.capacity() {
            return;
        }
        let doubled = self.bytes.capacity().checked_mul(2).unwrap_or(required);
        let capacity = required.max(doubled).max(8);
        // Establish the replacement's wiping owner before copying any bytes.
        // The explicit reservation guarantees this extend cannot reallocate.
        let mut replacement = Scratch {
            bytes: Vec::with_capacity(capacity),
        };
        replacement.bytes.extend_from_slice(&self.bytes);
        mem::swap(self, &mut replacement);
        // Drop wipes the old full allocation before deallocating it.
    }

    pub(crate) fn push(&mut self, byte: u8) {
        self.reserve(1);
        self.bytes.push(byte);
    }

    pub(crate) fn extend_from_slice(&mut self, bytes: &[u8]) {
        self.reserve(bytes.len());
        self.bytes.extend_from_slice(bytes);
    }

    pub(crate) fn clear(&mut self) {
        // Every removed byte is wiped here or in truncate/pop. Wiping only the
        // current initialized contents avoids re-erasing a large retained
        // allocation for every short string that follows it.
        self.bytes.as_mut_slice().zeroize();
        self.bytes.clear();
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        if len < self.bytes.len() {
            self.bytes[len..].zeroize();
            self.bytes.truncate(len);
        }
    }

    pub(crate) fn pop(&mut self) -> Option<u8> {
        let last = match self.bytes.last_mut() {
            Some(last) => last,
            None => return None,
        };
        let value = *last;
        last.zeroize();
        let _ = self.bytes.pop();
        Some(value)
    }

    #[cfg(feature = "raw_value")]
    fn into_vec(mut self) -> Vec<u8> {
        mem::take(&mut self.bytes)
    }

    #[cfg(feature = "raw_value")]
    fn into_boxed_slice(mut self) -> Box<[u8]> {
        if self.bytes.len() != self.bytes.capacity() {
            // Shrinking a live Vec may free its old plaintext allocation.
            // Shrink only zero-filled storage, then establish a guarded owner
            // with exact capacity before copying the initialized source bytes.
            let mut replacement = Scratch {
                bytes: alloc::vec![0; self.bytes.len()]
                    .into_boxed_slice()
                    .into_vec(),
            };
            replacement.bytes.copy_from_slice(&self.bytes);
            mem::swap(&mut self, &mut replacement);
        }
        // Capacity equals length, so this ownership transfer cannot shrink.
        self.into_vec().into_boxed_slice()
    }
}

#[cfg(feature = "raw_value")]
impl crate::io::Write for Scratch {
    fn write(&mut self, value: &[u8]) -> crate::io::Result<usize> {
        self.extend_from_slice(value);
        Ok(value.len())
    }

    fn write_all(&mut self, value: &[u8]) -> crate::io::Result<()> {
        self.extend_from_slice(value);
        Ok(())
    }

    fn flush(&mut self) -> crate::io::Result<()> {
        Ok(())
    }
}

impl Deref for Scratch {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Extend<u8> for Scratch {
    fn extend<I: IntoIterator<Item = u8>>(&mut self, iter: I) {
        for byte in iter {
            self.push(byte);
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        self.bytes.zeroize();
    }
}

/// Error messages can contain decoded input. Format directly into a guarded
/// owner so growth and error destruction erase every owned message copy.
pub(crate) struct GuardedString(Scratch);

impl GuardedString {
    pub(crate) fn from_display(value: impl Display) -> Self {
        let mut message = GuardedString(Scratch::new());
        fmt::write(&mut message, format_args!("{}", value))
            .expect("a Display implementation returned an error unexpectedly");
        message
    }

    pub(crate) fn truncate(&mut self, len: usize) {
        assert!(self.is_char_boundary(len));
        self.0.truncate(len);
    }

    #[cfg(feature = "raw_value")]
    pub(crate) fn from_str(value: &str) -> Self {
        let mut bytes = Scratch::new();
        bytes.extend_from_slice(value.as_bytes());
        GuardedString(bytes)
    }

    #[cfg(feature = "raw_value")]
    pub(crate) fn from_string(value: String) -> Self {
        GuardedString(Scratch {
            bytes: value.into_bytes(),
        })
    }

    #[cfg(feature = "raw_value")]
    pub(crate) fn from_utf8(bytes: Scratch) -> Result<Self, str::Utf8Error> {
        str::from_utf8(&bytes)?;
        Ok(GuardedString(bytes))
    }

    #[cfg(feature = "raw_value")]
    fn into_string(self) -> String {
        // SAFETY: construction and truncation preserve the UTF-8 invariant.
        unsafe { String::from_utf8_unchecked(self.0.into_vec()) }
    }

    #[cfg(feature = "raw_value")]
    pub(crate) fn into_boxed_str(self) -> Box<str> {
        let bytes = self.0.into_boxed_slice();
        // SAFETY: bytes is valid UTF-8 and both fat pointers retain the same
        // data pointer, length and allocation layout. Ownership moves once.
        unsafe { Box::from_raw(Box::into_raw(bytes) as *mut str) }
    }
}

impl Deref for GuardedString {
    type Target = str;

    fn deref(&self) -> &str {
        // Every write originates from a valid &str and truncation preserves a
        // character boundary. Check the invariant before exposing a string.
        str::from_utf8(&self.0).expect("guarded error messages are UTF-8")
    }
}

impl Write for GuardedString {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.0.extend_from_slice(value.as_bytes());
        Ok(())
    }
}

/// Retain private ownership while a seed can reject the deserializer itself.
/// Match Serde's StringDeserializer callbacks, handing off the ordinary String
/// only when visit_string is actually called. The receiving visitor then owns
/// that public value, including its errors, unwinding and eventual destruction.
#[cfg(feature = "raw_value")]
pub(crate) struct GuardedStringDeserializer(GuardedString);

#[cfg(feature = "raw_value")]
impl<'de> IntoDeserializer<'de, Error> for GuardedString {
    type Deserializer = GuardedStringDeserializer;

    fn into_deserializer(self) -> Self::Deserializer {
        GuardedStringDeserializer(self)
    }
}

#[cfg(feature = "raw_value")]
impl<'de> de::Deserializer<'de> for GuardedStringDeserializer {
    type Error = Error;

    fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_string(self.0.into_string())
    }

    fn deserialize_enum<V>(
        self,
        _name: &str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        visitor.visit_enum(self)
    }

    forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option unit unit_struct newtype_struct seq tuple
        tuple_struct map struct identifier ignored_any
    }
}

#[cfg(feature = "raw_value")]
impl<'de> EnumAccess<'de> for GuardedStringDeserializer {
    type Error = Error;
    type Variant = GuardedUnitVariant;

    fn variant_seed<T>(self, seed: T) -> Result<(T::Value, Self::Variant), Error>
    where
        T: DeserializeSeed<'de>,
    {
        seed.deserialize(self)
            .map(|value| (value, GuardedUnitVariant))
    }
}

#[cfg(feature = "raw_value")]
pub(crate) struct GuardedUnitVariant;

#[cfg(feature = "raw_value")]
impl<'de> VariantAccess<'de> for GuardedUnitVariant {
    type Error = Error;

    fn unit_variant(self) -> Result<(), Error> {
        Ok(())
    }

    fn newtype_variant_seed<T>(self, _seed: T) -> Result<T::Value, Error>
    where
        T: DeserializeSeed<'de>,
    {
        Err(de::Error::invalid_type(
            de::Unexpected::UnitVariant,
            &"newtype variant",
        ))
    }

    fn tuple_variant<V>(self, _len: usize, _visitor: V) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(de::Error::invalid_type(
            de::Unexpected::UnitVariant,
            &"tuple variant",
        ))
    }

    fn struct_variant<V>(
        self,
        _fields: &'static [&'static str],
        _visitor: V,
    ) -> Result<V::Value, Error>
    where
        V: Visitor<'de>,
    {
        Err(de::Error::invalid_type(
            de::Unexpected::UnitVariant,
            &"struct variant",
        ))
    }
}
