#![no_main]
//! Coverage-guided fuzzing of TOML config parsing, validation, and geometry
//! derivation. Any input must resolve to Ok/Err without panicking; a parsed
//! config must survive `validate()` and `geometry()` without panicking on
//! any accepted-then-inspected value.

use libfuzzer_sys::fuzz_target;

use maki_format::config::parse_config;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    if let Ok(cfg) = parse_config(text) {
        let _ = cfg.validate();
        let _ = cfg.geometry();
    }
});
