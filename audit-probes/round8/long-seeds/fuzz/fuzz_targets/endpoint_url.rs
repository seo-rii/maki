#![no_main]
//! Coverage-guided fuzzing of the endpoint-URL parser (scheme/host/userinfo
//! and the loopback plaintext policy). It must classify any string without
//! panicking.

use libfuzzer_sys::fuzz_target;

use maki_format::config::parse_endpoint_url;

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = parse_endpoint_url(text);
    }
});
