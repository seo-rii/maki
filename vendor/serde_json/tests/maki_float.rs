//! Inspect the production lexical owners, including their intermediate limbs.
// The imported upstream modules share the existing lexical fixture's style.
// Re-including Bigint exposes its real implementation to these tests without
// widening the production module's visibility.
#![allow(
    dead_code,
    clippy::duplicate_mod,
    clippy::needless_late_init,
    clippy::question_mark
)]

extern crate alloc;

mod maki_allocator;
use maki_allocator::{assert_all_wiped, assert_watched, observe, observe_aligned, watch};

#[path = "../src/lexical/mod.rs"]
mod lexical;
use lexical::math::{self, Limb, Math};
#[path = "../src/lexical/bignum.rs"]
mod bignum;
use bignum::Bigint;

fn bigint(limbs: &[Limb]) -> Bigint {
    let mut value = Bigint::default();
    value.data.extend_from_slice(limbs);
    value
}

fn inspect_drop(value: Bigint) {
    let (_, inspection) = observe(|| {
        watch(value.data.as_ptr().cast());
        drop(value);
    });
    assert_watched(inspection);
}

#[test]
fn maki_float_bigint_drop_erases_full_capacity() {
    let value = bigint(&[Limb::MAX, 17, Limb::MAX]);
    assert!(value.data.capacity() > value.data.len());
    inspect_drop(value);
}

#[test]
fn maki_float_growth_erases_old_and_replacement_allocations() {
    let mut value = Bigint::default();
    let original_capacity = value.data.capacity();
    let limbs = vec![Limb::MAX; original_capacity];
    value.data.extend_from_slice(&limbs);
    let (_, inspection) = observe(|| {
        watch(value.data.as_ptr().cast());
        value.imul_small(3);
    });
    assert_watched(inspection);
    assert_eq!(value.data.len(), original_capacity + 1);
    assert_eq!(value.data[0], Limb::MAX - 2);
    assert_eq!(value.data[original_capacity], 2);
    inspect_drop(value);
}

#[test]
fn maki_float_pop_and_resize_erase_removed_limbs_while_owner_is_live() {
    let mut value = bigint(&[11, Limb::MAX, Limb::MAX]);
    assert_eq!(value.data.pop(), Some(Limb::MAX));
    // SAFETY: the owner retains its allocation. This previously initialized
    // limb is now spare capacity, and our allocator initializes full layouts.
    assert_eq!(unsafe { *value.data.allocation_ptr().add(2) }, 0);
    value.data.resize(1, 0);
    // SAFETY: as above, this removed limb is in the same live allocation.
    assert_eq!(unsafe { *value.data.allocation_ptr().add(1) }, 0);
    assert_eq!(value.data.as_slice(), &[11]);
    inspect_drop(value);
}

#[test]
fn maki_float_clone_owners_are_independent_and_erased() {
    let mut original = bigint(&[Limb::MAX, 31]);
    let cloned = original.clone();
    assert_ne!(original.data.as_ptr(), cloned.data.as_ptr());
    original.iadd_small(1);
    assert_eq!(cloned.data.as_slice(), &[Limb::MAX, 31]);
    inspect_drop(original);
    inspect_drop(cloned);
}

#[test]
fn maki_float_multiplication_assignment_erases_replaced_owner() {
    let mut value = bigint(&[3, 17, Limb::MAX]);
    let (_, inspection) = observe(|| {
        watch(value.data.as_ptr().cast());
        value.imul_pow5(2048);
    });
    assert_watched(inspection);
    assert!(value.bit_length() > 2048);
    inspect_drop(value);
}

fn check_multiplication(limbs: &[Limb], power: u32) {
    // The one-less exponent uses a different decomposition. Build the oracle
    // and its caller-owned input before observing any private allocations.
    let mut expected = bigint(limbs);
    expected.imul_pow5(power - 1);
    expected.imul_small(5);
    let (same, inspection) = observe_aligned(core::mem::align_of::<Limb>(), || {
        let mut value = bigint(limbs);
        value.imul_pow5(power);
        let same = value.data.as_slice() == expected.data.as_slice();
        drop(value);
        same
    });
    assert!(same, "multiplication changed the exact integer");
    assert_all_wiped(inspection);
    assert!(
        inspection.frees > 10,
        "fixture did not exercise intermediate owners"
    );
}

#[test]
fn maki_float_balanced_karatsuba_erases_every_intermediate_allocation() {
    // 5^(Limb::BITS * 16) occupies about 38 limbs on both actual targets.
    check_multiplication(&[Limb::MAX; 33], Limb::BITS * 16);
}

#[test]
fn maki_float_uneven_karatsuba_and_long_mul_erase_every_intermediate_allocation() {
    check_multiplication(&[Limb::MAX; 7], 2048);
}

#[test]
fn maki_float_unwind_erases_owned_limbs_before_returning_panic_payload() {
    let value = bigint(&[Limb::MAX; 11]);
    let (result, inspection) = observe(|| {
        std::panic::catch_unwind(move || {
            watch(value.data.as_ptr().cast());
            let _owned = value;
            panic!("test arithmetic owner unwind");
        })
    });
    assert!(result.is_err());
    assert_watched(inspection);
    drop(result); // Rust owns the panic payload; release it outside observation.
}

#[test]
fn maki_float_slow_parser_erases_limbs_and_preserves_float_bits() {
    assert_eq!(
        lexical::parse_concise_float::<f64>(12345, -4).to_bits(),
        1.2345_f64.to_bits()
    );
    // These exact halfway inputs force the arbitrary-precision comparison;
    // merely supplying many digits can still finish in the moderate path.
    let fraction = b"00000000000000011102230246251565404236316680908203125";
    let (bits, inspection) = observe_aligned(core::mem::align_of::<Limb>(), || {
        lexical::parse_truncated_float::<f64>(b"1", fraction, 0).to_bits()
    });
    assert_eq!(bits, 1.0_f64.to_bits());
    assert_all_wiped(inspection);
    let fraction = b"000000178813934326171875";
    let (bits, inspection) = observe_aligned(core::mem::align_of::<Limb>(), || {
        lexical::parse_truncated_float::<f32>(b"1", fraction, 0).to_bits()
    });
    assert_eq!(bits, 1.0000002_f32.to_bits());
    assert_all_wiped(inspection);
}

#[test]
fn maki_float_shift_growth_erases_old_owner_and_preserves_padding() {
    let mut value = bigint(&[17, Limb::MAX, 31]);
    let padding = value.data.capacity() + 3;
    let (_, inspection) = observe(|| {
        watch(value.data.as_ptr().cast());
        value.ishl(padding * core::mem::size_of::<Limb>() * 8);
    });
    assert_watched(inspection);
    assert!(value.data[..padding].iter().all(|limb| *limb == 0));
    assert_eq!(&value.data[padding..], &[17, Limb::MAX, 31]);
    inspect_drop(value);
}

#[test]
fn maki_float_clone_from_erases_replaced_destination() {
    let source = bigint(&[Limb::MAX, 29]);
    let mut destination = bigint(&[17, Limb::MAX, 31]);
    let (_, inspection) = observe(|| {
        watch(destination.data.as_ptr().cast());
        destination.data.clone_from(&source.data);
    });
    assert_watched(inspection);
    assert_eq!(destination.data.as_slice(), source.data.as_slice());
    inspect_drop(destination);
    inspect_drop(source);
}

#[test]
fn maki_float_observer_preserves_byte_selection_and_isolates_limb_mode() {
    let (_, inspection) = observe(|| drop(vec![b'Q'; 32]));
    assert_eq!(inspection.secret_frees, 1);
    let (_, inspection) = observe_aligned(core::mem::align_of::<Limb>(), || {
        drop(vec![b'Q'; 32]); // A caller/runtime byte allocation is not a limb.
        drop(bigint(&[Limb::MAX; 3]));
    });
    assert_eq!(inspection.allocations, 1);
    assert_all_wiped(inspection);
}

#[cfg(all(feature = "float_roundtrip", feature = "std"))]
#[test]
fn maki_float_json_inputs_preserve_exact_halfway_bits_and_erase_limbs() {
    let wire = "1.00000000000000011102230246251565404236316680908203125";
    for input in 0..3 {
        let (bits, inspection) = observe_aligned(core::mem::align_of::<Limb>(), || {
            let value = match input {
                0 => serde_json::from_str::<f64>(wire),
                1 => serde_json::from_slice::<f64>(wire.as_bytes()),
                _ => serde_json::from_reader::<_, f64>(wire.as_bytes()),
            };
            value.unwrap().to_bits()
        });
        assert_eq!(bits, 1.0_f64.to_bits());
        assert_all_wiped(inspection);
    }
    let wire = "1.000000178813934326171875";
    let (bits, inspection) = observe_aligned(core::mem::align_of::<Limb>(), || {
        serde_json::from_str::<f32>(wire).unwrap().to_bits()
    });
    assert_eq!(bits, 1.0000002_f32.to_bits());
    assert_all_wiped(inspection);
}

#[cfg(all(feature = "float_roundtrip", feature = "std"))]
#[test]
fn maki_float_long_json_success_and_errors_erase_digit_scratch() {
    use maki_allocator::assert_wiped;
    let fraction = "7".repeat(1025);
    let wire = format!("0.{fraction}");
    let (value, inspection) = observe(|| serde_json::from_str::<f64>(&wire));
    assert_eq!(value.unwrap().to_bits(), (7.0_f64 / 9.0).to_bits());
    assert_wiped(inspection);
    for suffix in ["e", "e+", "e-", "e+x", "e999999999999999999999999"] {
        let wire = format!("0.{fraction}{suffix}");
        let (result, inspection) = observe(|| serde_json::from_str::<f64>(&wire));
        assert!(result.is_err(), "accepted invalid or out-of-range exponent");
        assert_wiped(inspection);
        drop(result); // Caller-owned Error is not an internal limb allocation.
    }
}
