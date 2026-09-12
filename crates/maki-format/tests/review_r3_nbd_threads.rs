//! MAKI-037: accepted worker counts must be used without silent truncation.

use maki_format::config::{parse_config, NbdSection};

const FULL: &str = include_str!("data/full_config.toml");

#[test]
fn unsupported_runtime_worker_counts_are_rejected() {
    for threads in [257, u32::MAX, 0] {
        let mut config = parse_config(FULL).unwrap();
        config.nbd.threads = threads;
        let error = config
            .validate()
            .expect_err("the adapter must not silently replace an accepted worker count")
            .to_string();
        assert!(error.contains("nbd.threads"), "{threads}: {error}");
        assert!(error.contains("1..=256"), "{threads}: {error}");
    }
}

#[test]
fn runtime_worker_count_boundaries_and_default_are_supported() {
    let config = parse_config(FULL).unwrap();
    config.validate().unwrap();
    for threads in [1, NbdSection::default().threads, 256] {
        let mut config = config.clone();
        config.nbd.threads = threads;
        config.validate().unwrap();
    }
}
