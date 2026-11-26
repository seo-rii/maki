#![no_main]
//! See `maki_fuzz_harness::witness_rpc`.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    maki_fuzz_harness::witness_rpc(data);
});
