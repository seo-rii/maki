//! Round-5 documentation audit harness (scope `docs-config`).
//!
//! Parses every `*.toml` in `AUDIT5_ATTACH_SNIPPET_DIR` as an attach
//! configuration and resolves it for the volume named by the file stem's
//! part before the first `.` (e.g. `postgres-prod.packaging.toml` is
//! resolved for volume `postgres-prod`). Without the variable the test does
//! nothing, so it never fails the default suite.

use maki_privileged::config::{parse, AttachOverrides};

#[test]
fn audit5_docs_attach_snippets_parse_and_resolve() {
    let Ok(dir) = std::env::var("AUDIT5_ATTACH_SNIPPET_DIR") else {
        eprintln!("AUDIT5_ATTACH_SNIPPET_DIR unset; nothing to check");
        return;
    };
    let mut files: Vec<_> = std::fs::read_dir(&dir)
        .expect("snippet directory")
        .filter_map(|entry| entry.ok().map(|entry| entry.path()))
        .filter(|path| path.extension().is_some_and(|ext| ext == "toml"))
        .collect();
    files.sort();
    for path in &files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        let volume = name.split('.').next().unwrap();
        let text = std::fs::read_to_string(path).unwrap();
        match parse(&text) {
            Err(error) => println!("{name}: PARSE {error}"),
            Ok(config) => {
                match config.into_request(volume, AttachOverrides::default(), true) {
                    Ok(request) => println!("{name}: OK {request:?}"),
                    Err(error) => println!("{name}: INVALID {error}"),
                }
            }
        }
    }
    println!("checked {} files", files.len());
}
