#![no_main]
//! Coverage-guided fuzzing of the privileged helper's pure parsers, which
//! read `/proc/self/mountinfo` and sysfs names. None may panic on malformed
//! input. `resolve_leaf_devices` is walked with a synthetic slaves relation
//! derived from the input to exercise cycles and deep chains.

use libfuzzer_sys::fuzz_target;

use maki_privileged::probe::{
    choose_free_nbd, nbd_device_of, nbd_index, parse_mountinfo, resolve_leaf_devices,
};

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let _ = parse_mountinfo(text, "/mnt/target");
    let _ = parse_mountinfo(text, text);
    for line in text.lines() {
        let _ = nbd_device_of(line);
        let _ = nbd_index(line);
    }

    // A synthetic sysfs `slaves` relation: a device's slaves are the
    // comma-separated tokens of its name (minus itself). Cycles and long
    // chains are possible; the walk must still terminate.
    let mut slaves = |name: &str| -> Vec<String> {
        name.split(',')
            .filter(|t| !t.is_empty() && *t != name)
            .map(str::to_string)
            .collect()
    };
    if let Some(start) = text.lines().next() {
        let _ = resolve_leaf_devices(start, &mut slaves);
    }

    // choose_free_nbd over a device list derived from the lines.
    let devices: Vec<(String, bool)> = text
        .lines()
        .map(|l| (l.to_string(), l.len() % 2 == 0))
        .collect();
    let _ = choose_free_nbd(&devices);
});
