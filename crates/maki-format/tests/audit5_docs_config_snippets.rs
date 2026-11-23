//! Round-5 documentation audit harness (scope `docs-config`).
//!
//! Parses and validates every `*.toml` file in the directory named by
//! `AUDIT5_SNIPPET_DIR` with the real `parse_config` + `validate`, and prints
//! one line per file. Without the variable the test does nothing, so it never
//! fails the default suite. Files named `expect-fail-*` are expected to be
//! refused; everything else is expected to load.
//!
//! Run:
//! AUDIT5_SNIPPET_DIR=/path/to/cases cargo test -p maki-format --locked \
//!   --test audit5_docs_config_snippets -- --nocapture --test-threads=2

use maki_format::config::parse_config;

#[test]
fn audit5_docs_config_snippets_parse_and_validate() {
    let Ok(dir) = std::env::var("AUDIT5_SNIPPET_DIR") else {
        eprintln!("AUDIT5_SNIPPET_DIR unset; nothing to check");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("snippet directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    let mut unexpected = 0;
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let text = std::fs::read_to_string(path).unwrap();
        let outcome = match parse_config(&text) {
            Err(error) => Err(format!("PARSE {error}")),
            Ok(config) => match config.validate() {
                Err(error) => Err(format!("INVALID {error}")),
                Ok(()) => Ok(config),
            },
        };
        let expect_fail = name.starts_with("expect-fail-");
        match &outcome {
            Ok(config) => {
                let geometry = config.geometry().unwrap();
                println!(
                    "{} {name}: OK effective_batch_max_items={} preferred_io={} slot_size={} plan={:?}",
                    if expect_fail { "UNEXPECTED" } else { "ok" },
                    config.effective_batch_max_items(),
                    config.nbd_preferred_io(),
                    geometry.slot_size,
                    geometry.capacity_plan().unwrap(),
                );
                if expect_fail {
                    unexpected += 1;
                }
            }
            Err(message) => {
                println!(
                    "{} {name}: {message}",
                    if expect_fail { "ok(refused)" } else { "UNEXPECTED" }
                );
                if !expect_fail {
                    unexpected += 1;
                }
            }
        }
    }
    println!("checked {} files, {unexpected} unexpected", files.len());
}
