//! Inspect allocations while live, and distinguish private buffers from caller outputs.
#![cfg(all(feature = "raw_value", feature = "std"))]

use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, VariantAccess, Visitor};
use serde::ser::{SerializeSeq, SerializeStruct};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::value::{to_raw_value, RawValue};
use std::fmt;
use std::io;

const TOKEN: &str = "$serde_json::private::RawValue";
mod maki_allocator;
use maki_allocator::{assert_watched, assert_wiped, observe, watch};

fn wire() -> String {
    format!("\"{}\"", "Q".repeat(1025))
}

#[test]
fn realloc_from_an_unselected_layout_keeps_observed_spare_capacity_initialized() {
    let (_, inspection) = observe(|| {
        let mut bytes = Vec::with_capacity(7);
        assert_eq!(bytes.capacity(), 7);
        bytes.push(0u8);
        bytes.reserve_exact(7);
        assert_eq!(bytes.capacity(), 8);
        // SAFETY: this test allocator initializes every allocation in full,
        // including an old capacity below the observer's selected size range.
        let allocation = unsafe { std::slice::from_raw_parts(bytes.as_ptr(), bytes.capacity()) };
        assert!(allocation.iter().all(|byte| *byte == 0));
        drop(bytes);
    });
    assert_wiped(inspection);
}

#[test]
fn reader_growth_erases_private_storage_and_keeps_returned_raw_value() {
    let wire = wire();
    let (raw, inspection) =
        observe(|| serde_json::from_reader::<_, Box<RawValue>>(wire.as_bytes()).unwrap());
    assert_eq!(raw.get(), wire);
    assert_wiped(inspection);
    // Caller-owned output remains intact and is dropped after observation.
    drop(raw);
}

#[test]
fn reader_json_and_utf8_errors_erase_partial_raw_storage() {
    let valid = wire();
    let missing_quote = &valid[..valid.len() - 1];
    let mut invalid_utf8 = valid.as_bytes().to_vec();
    let last_character = invalid_utf8.len() - 2;
    invalid_utf8[last_character] = 0xff;
    for input in [missing_quote.as_bytes(), invalid_utf8.as_slice()] {
        let (result, inspection) = observe(|| serde_json::from_reader::<_, Box<RawValue>>(input));
        assert!(result.is_err());
        assert_wiped(inspection);
        drop(result);
    }
}

struct FailingReader<'a> {
    remaining: &'a [u8],
}

impl io::Read for FailingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.remaining.is_empty() {
            return Err(io::ErrorKind::Other.into());
        }
        let length = output.len().min(self.remaining.len());
        output[..length].copy_from_slice(&self.remaining[..length]);
        self.remaining = &self.remaining[length..];
        Ok(length)
    }
}

#[test]
fn reader_io_error_erases_partial_raw_storage() {
    let wire = wire();
    let (result, inspection) = observe(|| {
        serde_json::from_reader::<_, Box<RawValue>>(FailingReader {
            remaining: &wire.as_bytes()[..wire.len() - 1],
        })
    });
    assert!(result.unwrap_err().is_io());
    assert_wiped(inspection);
}

struct RejectSeed;
impl<'de> DeserializeSeed<'de> for RejectSeed {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _deserializer: D) -> Result<(), D::Error> {
        Err(de::Error::custom("seed rejected raw value"))
    }
}

struct PanicSeed;
impl<'de> DeserializeSeed<'de> for PanicSeed {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _deserializer: D) -> Result<(), D::Error> {
        panic!("raw seed panic before deserialization")
    }
}

struct RejectEnumSeed<const ACTION: u8>;
impl<'de, const ACTION: u8> DeserializeSeed<'de> for RejectEnumSeed<ACTION> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct EnumVisitor<const ACTION: u8>;
        impl<'de, const ACTION: u8> Visitor<'de> for EnumVisitor<ACTION> {
            type Value = ();
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a raw enum")
            }
            fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<(), A::Error> {
                if ACTION == 1 {
                    access.variant_seed(RejectSeed)?;
                } else if ACTION == 2 {
                    panic!("raw enum panic before string handoff");
                } else if ACTION == 3 {
                    access.variant_seed(PanicSeed)?;
                }
                Err(de::Error::custom("enum rejected raw value"))
            }
        }
        deserializer.deserialize_enum("Raw", &[], EnumVisitor::<ACTION>)
    }
}

struct DiscardRaw<const MODE: u8>;
impl<'de, const MODE: u8> Deserialize<'de> for DiscardRaw<MODE> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RawVisitor<const MODE: u8>;
        impl<'de, const MODE: u8> Visitor<'de> for RawVisitor<MODE> {
            type Value = DiscardRaw<MODE>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a raw map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                if MODE == 0 {
                    return Ok(DiscardRaw);
                }
                if MODE == 1 {
                    map.next_key_seed(RejectSeed)?;
                    unreachable!();
                }
                assert_eq!(map.next_key::<String>()?.as_deref(), Some(TOKEN));
                match MODE {
                    2 => map.next_value_seed(RejectSeed)?,
                    3 => map.next_value_seed(PanicSeed)?,
                    4 => map.next_value_seed(RejectEnumSeed::<0>)?,
                    5 => map.next_value_seed(RejectEnumSeed::<1>)?,
                    6 => map.next_value_seed(RejectEnumSeed::<2>)?,
                    7 => map.next_value_seed(RejectEnumSeed::<3>)?,
                    _ => unreachable!(),
                }
                unreachable!()
            }
        }
        deserializer.deserialize_newtype_struct(TOKEN, RawVisitor::<MODE>)
    }
}

fn reader_rejection<const MODE: u8>() {
    let wire = wire();
    let (result, inspection) =
        observe(|| serde_json::from_reader::<_, DiscardRaw<MODE>>(wire.as_bytes()));
    assert!(result.is_err());
    assert_wiped(inspection);
    drop(result);
}

#[test]
fn raw_map_not_consumed_erases_private_owned_storage() {
    let wire = wire();
    let (_, inspection) =
        observe(|| serde_json::from_reader::<_, DiscardRaw<0>>(wire.as_bytes()).unwrap());
    assert_wiped(inspection);
}

#[test]
fn raw_map_key_and_value_seed_rejections_erase_private_owned_storage() {
    reader_rejection::<1>();
    reader_rejection::<2>();
}

#[test]
fn raw_map_seed_panic_erases_private_owned_storage() {
    let wire = wire();
    let (result, inspection) = observe(|| {
        std::panic::catch_unwind(|| {
            let _ = serde_json::from_reader::<_, DiscardRaw<3>>(wire.as_bytes());
        })
    });
    assert!(result.is_err());
    assert_wiped(inspection);
}

#[test]
fn enum_and_variant_seed_rejections_erase_storage_before_string_handoff() {
    reader_rejection::<4>();
    reader_rejection::<5>();
}

#[test]
fn enum_and_variant_seed_panics_erase_storage_before_string_handoff() {
    fn check<const MODE: u8>() {
        let wire = wire();
        let (result, inspection) = observe(|| {
            std::panic::catch_unwind(|| {
                let _ = serde_json::from_reader::<_, DiscardRaw<MODE>>(wire.as_bytes());
            })
        });
        assert!(result.is_err());
        assert_wiped(inspection);
    }
    check::<6>();
    check::<7>();
}

#[test]
fn owned_and_borrowed_value_to_raw_erase_formatted_private_copies() {
    let value = serde_json::Value::String("Q".repeat(1025));
    let (result, inspection) = observe(|| DiscardRaw::<2>::deserialize(&value));
    assert!(result.is_err());
    assert_eq!(value.as_str().unwrap(), "Q".repeat(1025));
    assert_wiped(inspection);
    drop(result);

    // This input is allocated before observation. Its preexisting public value
    // is excluded; only new private formatting allocations are inspected.
    let (result, inspection) = observe(|| serde_json::from_value::<DiscardRaw<2>>(value));
    assert!(result.is_err());
    assert_wiped(inspection);
    drop(result);
}

#[test]
fn raw_token_to_value_erases_the_internal_raw_parse_temporary() {
    let raw_wire = wire();
    let encoded = serde_json::to_string(&raw_wire).unwrap();
    let input = format!("{{\"{TOKEN}\":{encoded}}}");
    let (value, inspection) =
        observe(|| serde_json::from_str::<serde_json::Value>(&input).unwrap());
    assert_eq!(value.as_str().unwrap(), "Q".repeat(1025));
    assert_wiped(inspection);
    drop(value);

    let invalid = serde_json::to_string(&raw_wire[..raw_wire.len() - 1]).unwrap();
    let input = format!("{{\"{TOKEN}\":{invalid}}}");
    let (result, inspection) = observe(|| serde_json::from_str::<serde_json::Value>(&input));
    assert!(result.is_err());
    assert_wiped(inspection);
    drop(result);
}

struct DisplayRaw<'a>(&'a str);
impl fmt::Display for DisplayRaw<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str(self.0)
    }
}
impl Serialize for DisplayRaw<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

struct TokenDisplay<'a>(&'a str);
impl Serialize for TokenDisplay<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut raw = serializer.serialize_struct(TOKEN, 1)?;
        raw.serialize_field(TOKEN, &DisplayRaw(self.0))?;
        raw.end()
    }
}

#[test]
fn raw_collect_str_erases_internal_display_copies_for_wire_and_value_serializers() {
    let wire = wire();
    let (output, inspection) = observe(|| serde_json::to_vec(&TokenDisplay(&wire)).unwrap());
    assert_eq!(output, wire.as_bytes());
    assert_wiped(inspection);
    drop(output);
    let (output, inspection) = observe(|| serde_json::to_value(TokenDisplay(&wire)).unwrap());
    assert_eq!(output.as_str().unwrap(), "Q".repeat(1025));
    assert_wiped(inspection);
    drop(output);
}

struct FailSerialize<'a>(&'a str);
impl Serialize for FailSerialize<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        sequence.serialize_element(self.0)?;
        Err(serde::ser::Error::custom("failure after raw payload"))
    }
}

struct PanicSerialize<'a>(&'a str);
impl Serialize for PanicSerialize<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut sequence = serializer.serialize_seq(Some(2))?;
        sequence.serialize_element(self.0)?;
        panic!("raw serializer panic after payload")
    }
}

#[test]
fn raw_value_serialization_erases_growth_and_preserves_returned_output() {
    let payload = "Q".repeat(1025);
    let expected = wire();
    let (raw, inspection) = observe(|| to_raw_value(&payload).unwrap());
    assert_eq!(raw.get(), expected);
    assert_wiped(inspection);
    drop(raw);
}

#[test]
fn raw_value_serialization_error_and_panic_erase_partial_output() {
    let payload = "Q".repeat(1025);
    let (result, inspection) = observe(|| to_raw_value(&FailSerialize(&payload)));
    assert!(result.is_err());
    assert_wiped(inspection);
    drop(result);
    let (result, inspection) = observe(|| {
        std::panic::catch_unwind(|| {
            let _ = to_raw_value(&PanicSerialize(&payload));
        })
    });
    assert!(result.is_err());
    assert_wiped(inspection);
}

#[test]
fn raw_string_whitespace_and_shrink_erase_abandoned_source_storage() {
    let wire = wire();
    for whitespace in [false, true] {
        let (raw, inspection) = observe(|| {
            let mut source = String::with_capacity(wire.len() + 64);
            if whitespace {
                source.push_str(" \n");
            }
            source.push_str(&wire);
            if whitespace {
                source.push_str(" \t");
            }
            RawValue::from_string(source).unwrap()
        });
        assert_eq!(raw.get(), wire);
        assert_wiped(inspection);
        drop(raw);
    }
    let (raw, inspection) = observe(|| {
        let mut source = String::with_capacity(wire.len() + 64);
        source.push_str(&wire);
        // SAFETY: wire is one well-formed JSON value without outer whitespace.
        unsafe { RawValue::from_string_unchecked(source) }
    });
    assert_eq!(raw.get(), wire);
    assert_wiped(inspection);
    drop(raw);
}

#[test]
fn invalid_owned_raw_string_erases_source_storage() {
    let wire = wire();
    let (result, inspection) = observe(|| {
        let source = wire[..wire.len() - 1].to_owned();
        watch(source.as_ptr());
        RawValue::from_string(source)
    });
    assert!(result.is_err());
    assert_wiped(inspection);
    assert_watched(inspection);
    drop(result);
}

struct OwnedStringSeed;
impl<'de> DeserializeSeed<'de> for OwnedStringSeed {
    type Value = String;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        struct StringVisitor;
        impl Visitor<'_> for StringVisitor {
            type Value = String;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("an owned string")
            }
            fn visit_string<E: de::Error>(self, value: String) -> Result<String, E> {
                Ok(value)
            }
        }
        deserializer.deserialize_string(StringVisitor)
    }
}

struct EnumVariantSeed<const MODE: u8>;
impl<'de, const MODE: u8> DeserializeSeed<'de> for EnumVariantSeed<MODE> {
    type Value = String;
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<String, D::Error> {
        struct AnyVariant;
        impl Visitor<'_> for AnyVariant {
            type Value = ();
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a variant")
            }
        }
        struct EnumVisitor<const MODE: u8>;
        impl<'de, const MODE: u8> Visitor<'de> for EnumVisitor<MODE> {
            type Value = String;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a raw enum")
            }
            fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<String, A::Error> {
                let (name, variant) = access.variant_seed(OwnedStringSeed)?;
                match MODE {
                    0 => variant.unit_variant()?,
                    1 => {
                        let _: String = variant.newtype_variant()?;
                    }
                    2 => variant.tuple_variant(0, AnyVariant)?,
                    3 => variant.struct_variant(&[], AnyVariant)?,
                    _ => unreachable!(),
                }
                Ok(name)
            }
        }
        deserializer.deserialize_enum("Raw", &[], EnumVisitor::<MODE>)
    }
}

struct OwnedRaw<const ENUM_MODE: u8>(String);
impl<'de, const ENUM_MODE: u8> Deserialize<'de> for OwnedRaw<ENUM_MODE> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RawVisitor<const MODE: u8>;
        impl<'de, const MODE: u8> Visitor<'de> for RawVisitor<MODE> {
            type Value = OwnedRaw<MODE>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a raw map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                assert_eq!(map.next_key::<String>()?.as_deref(), Some(TOKEN));
                let value = if MODE == 255 {
                    map.next_value_seed(OwnedStringSeed)?
                } else {
                    map.next_value_seed(EnumVariantSeed::<MODE>)?
                };
                Ok(OwnedRaw(value))
            }
        }
        deserializer.deserialize_newtype_struct(TOKEN, RawVisitor::<ENUM_MODE>)
    }
}

#[test]
fn owned_string_callback_and_enum_unit_variant_keep_their_semantics() {
    let wire = "\"caller\"";
    let raw: OwnedRaw<255> = serde_json::from_reader(wire.as_bytes()).unwrap();
    assert_eq!(raw.0, wire);
    let raw: OwnedRaw<0> = serde_json::from_reader(wire.as_bytes()).unwrap();
    assert_eq!(raw.0, wire);
}

#[test]
fn enum_non_unit_variant_errors_match_standard_string_deserializer() {
    let wire = "\"caller\"";
    fn check<const MODE: u8>(wire: &str) {
        let actual = serde_json::from_reader::<_, OwnedRaw<MODE>>(wire.as_bytes())
            .err()
            .unwrap();
        let expected = EnumVariantSeed::<MODE>
            .deserialize(
                serde::de::value::StringDeserializer::<serde_json::Error>::new(wire.to_owned()),
            )
            .unwrap_err();
        assert_eq!(actual.to_string(), expected.to_string());
        assert_eq!(actual.classify(), expected.classify());
    }
    check::<1>(wire);
    check::<2>(wire);
    check::<3>(wire);
}

#[test]
fn borrowed_raw_and_exact_capacity_public_box_preserve_the_source() {
    let wire = wire();
    let (raw, inspection) = observe(|| serde_json::from_str::<&RawValue>(&wire).unwrap());
    assert_eq!(raw.get().as_ptr(), wire.as_ptr());
    assert_eq!(raw.get(), wire);
    assert_eq!(inspection.secret_frees, 0);
    assert!(!inspection.overflowed);

    let source = wire.clone();
    assert_eq!(source.len(), source.capacity());
    let pointer = source.as_ptr();
    let raw = RawValue::from_string(source).unwrap();
    assert_eq!(raw.get().as_ptr(), pointer);
    assert_eq!(raw.get(), wire);
    let boxed: Box<str> = raw.into();
    assert_eq!(&*boxed, wire);
}
