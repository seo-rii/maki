//! Erase parser-private number storage while retaining public Number outputs.
#![cfg(all(feature = "arbitrary_precision", feature = "std"))]

mod maki_allocator;
use maki_allocator::{assert_watched, assert_wiped, observe, watch};
use serde::de::{self, DeserializeSeed, EnumAccess, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Number, Value};
use std::fmt;
use std::io;

const TOKEN: &str = "$serde_json::private::Number";

fn large_number() -> String {
    "7".repeat(1025)
}

#[derive(Debug, PartialEq)]
enum Numeric {
    U64(u64),
    I64(i64),
    U128(u128),
    I128(i128),
    F64(u64),
}

impl<'de> Deserialize<'de> for Numeric {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NumericVisitor;
        impl<'de> Visitor<'de> for NumericVisitor {
            type Value = Numeric;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a primitive number")
            }

            fn visit_u64<E: de::Error>(self, n: u64) -> Result<Numeric, E> {
                Ok(Numeric::U64(n))
            }

            fn visit_i64<E: de::Error>(self, n: i64) -> Result<Numeric, E> {
                Ok(Numeric::I64(n))
            }

            fn visit_u128<E: de::Error>(self, n: u128) -> Result<Numeric, E> {
                Ok(Numeric::U128(n))
            }

            fn visit_i128<E: de::Error>(self, n: i128) -> Result<Numeric, E> {
                Ok(Numeric::I128(n))
            }

            fn visit_f64<E: de::Error>(self, n: f64) -> Result<Numeric, E> {
                Ok(Numeric::F64(n.to_bits()))
            }
        }
        deserializer.deserialize_any(NumericVisitor)
    }
}

#[test]
fn scanner_erases_integer_reduction_on_success_for_every_input() {
    for wire in ["7777777777777777777", "-777777777777777777"] {
        let (_, inspection) = observe(|| serde_json::from_str::<Numeric>(wire).unwrap());
        assert_wiped(inspection);
        let (_, inspection) =
            observe(|| serde_json::from_slice::<Numeric>(wire.as_bytes()).unwrap());
        assert_wiped(inspection);
        let (_, inspection) =
            observe(|| serde_json::from_reader::<_, Numeric>(wire.as_bytes()).unwrap());
        assert_wiped(inspection);
    }
}

#[test]
fn scanner_growth_and_internal_number_string_handoff_preserve_outputs() {
    let integer = large_number();
    for wire in [
        integer.clone(),
        format!("{integer}.777"),
        format!("{integer}E999"),
    ] {
        let expected = wire.replace('E', "e+");
        let (number, inspection) = observe(|| serde_json::from_str::<Number>(&wire).unwrap());
        assert_eq!(number.as_str(), expected);
        assert_wiped(inspection);
        let (number, inspection) =
            observe(|| serde_json::from_reader::<_, Number>(wire.as_bytes()).unwrap());
        assert_eq!(number.as_str(), expected);
        assert_wiped(inspection);
        // Public Number contents remain valid; ordinary Drop is caller-owned.
        drop(number);
    }
}

#[test]
fn scanner_errors_erase_partial_numbers_and_rejected_completed_numbers() {
    let integer = large_number();
    for suffix in [".", ".x", "e", "e+", "e-", "e+x", "x"] {
        let wire = format!("{integer}{suffix}");
        let (result, inspection) = observe(|| wire.parse::<Number>());
        assert!(result.is_err(), "accepted suffix {suffix}");
        assert_wiped(inspection);
        drop(result);
        let (result, inspection) =
            observe(|| serde_json::from_reader::<_, DiscardNumber<0>>(wire.as_bytes()));
        assert!(result.is_err(), "accepted suffix {suffix}");
        assert_wiped(inspection);
        drop(result);
    }
}

struct FailingReader<'a>(&'a [u8]);
impl io::Read for FailingReader<'_> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if self.0.is_empty() {
            return Err(io::ErrorKind::Other.into());
        }
        let length = output.len().min(self.0.len());
        output[..length].copy_from_slice(&self.0[..length]);
        self.0 = &self.0[length..];
        Ok(length)
    }
}

#[test]
fn scanner_io_error_erases_partial_number() {
    let wire = large_number();
    let (result, inspection) =
        observe(|| serde_json::from_reader::<_, Number>(FailingReader(wire.as_bytes())));
    assert!(result.unwrap_err().is_io());
    assert_wiped(inspection);
}

#[test]
fn scanner_type_mismatch_erases_completed_number() {
    let wire = large_number();
    let (result, inspection) = observe(|| serde_json::from_str::<bool>(&wire));
    assert!(result.unwrap_err().is_data());
    assert_wiped(inspection);
}

struct RejectSeed;
impl<'de> DeserializeSeed<'de> for RejectSeed {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _deserializer: D) -> Result<(), D::Error> {
        Err(de::Error::custom("number seed rejected before handoff"))
    }
}

struct PanicSeed;
impl<'de> DeserializeSeed<'de> for PanicSeed {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, _deserializer: D) -> Result<(), D::Error> {
        panic!("number seed panic before handoff");
    }
}

struct EnumSeed<const PANIC: bool>;
impl<'de, const PANIC: bool> DeserializeSeed<'de> for EnumSeed<PANIC> {
    type Value = ();
    fn deserialize<D: Deserializer<'de>>(self, deserializer: D) -> Result<(), D::Error> {
        struct EnumVisitor<const PANIC: bool>;
        impl<'de, const PANIC: bool> Visitor<'de> for EnumVisitor<PANIC> {
            type Value = ();
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a number enum")
            }
            fn visit_enum<A: EnumAccess<'de>>(self, access: A) -> Result<(), A::Error> {
                if PANIC {
                    access.variant_seed(PanicSeed)?;
                } else {
                    access.variant_seed(RejectSeed)?;
                }
                unreachable!()
            }
        }
        deserializer.deserialize_enum("Number", &[], EnumVisitor::<PANIC>)
    }
}

struct DiscardNumber<const MODE: u8>;
impl<'de, const MODE: u8> Deserialize<'de> for DiscardNumber<MODE> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct NumberVisitor<const MODE: u8>;
        impl<'de, const MODE: u8> Visitor<'de> for NumberVisitor<MODE> {
            type Value = DiscardNumber<MODE>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a number map")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                if MODE == 0 {
                    return Ok(DiscardNumber);
                }
                if MODE == 1 {
                    map.next_key_seed(RejectSeed)?;
                    unreachable!();
                }
                if MODE == 5 {
                    panic!("number map panic before handoff");
                }
                assert_eq!(map.next_key::<String>()?.as_deref(), Some(TOKEN));
                match MODE {
                    2 => return Ok(DiscardNumber),
                    3 => map.next_value_seed(RejectSeed)?,
                    4 => map.next_value_seed(PanicSeed)?,
                    6 => map.next_value_seed(EnumSeed::<false>)?,
                    7 => map.next_value_seed(EnumSeed::<true>)?,
                    _ => unreachable!(),
                }
                unreachable!()
            }
        }
        deserializer.deserialize_any(NumberVisitor::<MODE>)
    }
}

fn discard_map<const MODE: u8>() {
    let wire = large_number();
    let (result, inspection) = observe(|| serde_json::from_str::<DiscardNumber<MODE>>(&wire));
    assert_eq!(result.is_ok(), MODE == 0 || MODE == 2);
    assert_wiped(inspection);
}

#[test]
fn number_map_unconsumed_and_key_only_erase_private_storage() {
    discard_map::<0>();
    discard_map::<2>();
}

#[test]
fn number_map_key_value_and_enum_seed_rejections_erase_private_storage() {
    discard_map::<1>();
    discard_map::<3>();
    discard_map::<6>();
}

fn panic_map<const MODE: u8>() {
    let wire = large_number();
    let (result, inspection) = observe(|| {
        std::panic::catch_unwind(|| {
            let _ = serde_json::from_str::<DiscardNumber<MODE>>(&wire);
        })
    });
    assert!(result.is_err());
    assert_wiped(inspection);
}

#[test]
fn number_map_and_seed_panics_erase_private_storage() {
    panic_map::<4>();
    panic_map::<5>();
    panic_map::<7>();
}

fn token_value(number: String) -> Value {
    let mut map = serde_json::Map::new();
    map.insert(TOKEN.to_owned(), Value::String(number));
    Value::Object(map)
}

#[test]
fn internal_number_from_string_reacquires_owned_visitor_string_on_success_and_error() {
    let wire = large_number();
    let source = wire.clone();
    let (value, inspection) = observe(|| {
        watch(source.as_ptr());
        serde_json::from_value::<Value>(token_value(source)).unwrap()
    });
    assert_eq!(value.as_number().unwrap().as_str(), wire);
    assert_wiped(inspection);
    assert_watched(inspection);
    for suffix in ["x", "e+"] {
        // Construct public input before observing private consumption; format!
        // is allowed to grow and release its caller-owned string allocation.
        let source = format!("{wire}{suffix}");
        let (result, inspection) = observe(|| {
            watch(source.as_ptr());
            serde_json::from_value::<Number>(token_value(source))
        });
        assert!(result.is_err());
        assert_wiped(inspection);
        assert_watched(inspection);
        drop(result);
    }
}

#[test]
fn consumed_owned_number_primitive_dispatch_erases_source_and_keeps_callbacks() {
    for (wire, expected) in [
        ("7", Numeric::U64(7)),
        ("-7", Numeric::I64(-7)),
        ("0.7", Numeric::F64(0.7f64.to_bits())),
        ("7777777777777777777", Numeric::U64(7777777777777777777)),
        ("-777777777777777777", Numeric::I64(-777777777777777777)),
        (
            "77777777777777777777777777777777777777",
            Numeric::U128(77777777777777777777777777777777777777),
        ),
        (
            "-77777777777777777777777777777777777777",
            Numeric::I128(-77777777777777777777777777777777777777),
        ),
        (
            "7777777777777777.0",
            Numeric::F64(7777777777777777.0f64.to_bits()),
        ),
    ] {
        let (numeric, inspection) = observe(|| {
            let number = Number::from_string_unchecked(wire.to_owned());
            watch(number.as_str().as_ptr());
            Numeric::deserialize(number).unwrap()
        });
        assert_eq!(numeric, expected);
        assert_watched(inspection);
        if wire.len() >= 16 {
            assert_wiped(inspection);
        }
        assert_eq!(inspection.frees, inspection.wiped_frees);
    }
}

#[test]
fn consumed_owned_number_typed_success_and_failure_erase_source() {
    let (_, inspection) = observe(|| {
        let source = Number::from_string_unchecked("7777777777777777777".to_owned());
        watch(source.as_str().as_ptr());
        assert_eq!(u64::deserialize(source).unwrap(), 7777777777777777777);
    });
    assert_wiped(inspection);
    assert_watched(inspection);
    let (_, inspection) = observe(|| {
        let source = Number::from_string_unchecked("-777777777777777777".to_owned());
        watch(source.as_str().as_ptr());
        assert_eq!(i64::deserialize(source).unwrap(), -777777777777777777);
    });
    assert_wiped(inspection);
    assert_watched(inspection);
    let (_, inspection) = observe(|| {
        let source = Number::from_string_unchecked(large_number());
        watch(source.as_str().as_ptr());
        let result = u64::deserialize(source);
        assert!(result.is_err());
        drop(result);
    });
    assert_wiped(inspection);
    assert_watched(inspection);
    for wire in ["7", "x"] {
        let (_, inspection) = observe(|| {
            let source = Number::from_string_unchecked(wire.to_owned());
            watch(source.as_str().as_ptr());
            assert_eq!(u64::deserialize(source).is_ok(), wire == "7");
        });
        assert_watched(inspection);
    }
}

struct RejectNumeric<const PANIC: bool>;
impl<'de, const PANIC: bool> Deserialize<'de> for RejectNumeric<PANIC> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct RejectVisitor<const PANIC: bool>;
        impl<'de, const PANIC: bool> Visitor<'de> for RejectVisitor<PANIC> {
            type Value = RejectNumeric<PANIC>;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a rejected number")
            }
            fn visit_u64<E: de::Error>(self, _number: u64) -> Result<Self::Value, E> {
                if PANIC {
                    panic!("numeric callback panic");
                }
                Err(de::Error::custom("numeric callback rejected value"))
            }
        }
        deserializer.deserialize_u64(RejectVisitor::<PANIC>)
    }
}

#[test]
fn consumed_owned_number_callback_error_and_panic_erase_full_source_allocation() {
    let (_, inspection) = observe(|| {
        let mut wire = String::with_capacity(4096);
        wire.push_str("7777777777777777777");
        watch(wire.as_ptr());
        let result = RejectNumeric::<false>::deserialize(Number::from_string_unchecked(wire));
        assert!(result.is_err());
        drop(result);
    });
    assert_wiped(inspection);
    assert_watched(inspection);
    let (result, inspection) = observe(|| {
        std::panic::catch_unwind(|| {
            let mut wire = String::with_capacity(4096);
            wire.push_str("7777777777777777777");
            watch(wire.as_ptr());
            let _ = RejectNumeric::<true>::deserialize(Number::from_string_unchecked(wire));
        })
    });
    assert!(result.is_err());
    assert_wiped(inspection);
    assert_watched(inspection);
}

#[test]
fn borrowed_number_preserves_original_and_erases_only_private_map_copy() {
    let number = Number::from_string_unchecked(large_number());
    let pointer = number.as_str().as_ptr();
    let (result, inspection) = observe(|| DiscardNumber::<3>::deserialize(&number));
    assert!(result.is_err());
    assert_wiped(inspection);
    assert_eq!(number.as_str().as_ptr(), pointer);
    assert_eq!(number.as_str(), large_number());

    let small = Number::from_string_unchecked("7777777777777777777".to_owned());
    let (_, inspection) = observe(|| Numeric::deserialize(&small).unwrap());
    assert_eq!(
        inspection.allocations, 0,
        "borrowed scalar copied its source"
    );
    assert_eq!(small.as_str(), "7777777777777777777");
    assert_eq!(u64::deserialize(&small).unwrap(), 7777777777777777777);
}

#[test]
fn float_display_comparison_erases_temporary_and_keeps_exact_float_dispatch() {
    let float = 7.777777777777777e100f64;
    let wire = float.to_string();
    assert!(wire.contains("7777777777777777"));
    for owned in [false, true] {
        let number = Number::from_string_unchecked(wire.clone());
        let (numeric, inspection) = observe(|| {
            if owned {
                Numeric::deserialize(number)
            } else {
                Numeric::deserialize(&number)
            }
        });
        assert_eq!(numeric.unwrap(), Numeric::F64(float.to_bits()));
        assert_wiped(inspection);
    }
}

struct OwnedNumberString(String);
impl<'de> Deserialize<'de> for OwnedNumberString {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct MapVisitor;
        impl<'de> Visitor<'de> for MapVisitor {
            type Value = OwnedNumberString;
            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a number map with an owned string")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Self::Value, A::Error> {
                assert_eq!(map.next_key::<String>()?.as_deref(), Some(TOKEN));
                struct StringOnly(String);
                impl<'de> Deserialize<'de> for StringOnly {
                    fn deserialize<D: Deserializer<'de>>(
                        deserializer: D,
                    ) -> Result<Self, D::Error> {
                        struct StringVisitor;
                        impl<'de> Visitor<'de> for StringVisitor {
                            type Value = OwnedNumberString;
                            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                                formatter.write_str("an owned string")
                            }
                            fn visit_str<E: de::Error>(
                                self,
                                _value: &str,
                            ) -> Result<Self::Value, E> {
                                Err(de::Error::custom(
                                    "borrowed callback replaced owned handoff",
                                ))
                            }
                            fn visit_string<E: de::Error>(
                                self,
                                value: String,
                            ) -> Result<Self::Value, E> {
                                Ok(OwnedNumberString(value))
                            }
                        }
                        deserializer
                            .deserialize_string(StringVisitor)
                            .map(|value| StringOnly(value.0))
                    }
                }
                Ok(OwnedNumberString(map.next_value::<StringOnly>()?.0))
            }
        }
        deserializer.deserialize_any(MapVisitor)
    }
}

#[test]
fn public_owned_string_callback_receives_intact_source() {
    let wire = large_number();
    let (value, inspection) = observe(|| serde_json::from_str::<OwnedNumberString>(&wire).unwrap());
    assert_eq!(value.0, wire);
    assert_wiped(inspection);
    drop(value);
}

#[test]
fn public_number_spelling_and_serialization_remain_compatible() {
    for (input, expected) in [
        ("1E999", "1e+999"),
        ("1e+000", "1e+000"),
        ("-1e-999", "-1e-999"),
        ("0.0007777777777777777777", "0.0007777777777777777777"),
    ] {
        let number: Number = input.parse().unwrap();
        assert_eq!(number.as_str(), expected);
        assert_eq!(serde_json::to_string(&number).unwrap(), expected);
    }
}
