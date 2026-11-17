//! Audit probe (round 2): every complete configuration the repository ships
//! or documents (packaging/examples, examples/, TOML fences in Markdown with
//! `config_schema_version`) must still parse and validate after the round-1
//! validation rules (#159, #161). Failures caused only by files the host
//! lacks (TLS bundles, credential files) are environmental and reported
//! separately; any other refusal is printed and fails the test.

use std::path::{Path, PathBuf};

use maki_format::config::parse_config;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn markdown_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if ["target", "vendor", ".git", "historical-reviews"].contains(&name.as_ref()) {
                continue;
            }
            markdown_files(&path, out);
        } else if name.ends_with(".md") {
            out.push(path);
        }
    }
}

/// `(source, toml)` for every TOML fence that declares a full config.
fn fences(path: &Path) -> Vec<(String, String)> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    let mut lines = text.lines().enumerate();
    while let Some((number, line)) = lines.next() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("```toml") {
            let indent = line.len() - trimmed.len();
            let mut body = String::new();
            for (_, inner) in lines.by_ref() {
                if inner.trim_start().starts_with("```") {
                    break;
                }
                let stripped = if inner.len() >= indent && inner[..indent].trim().is_empty() {
                    &inner[indent..]
                } else {
                    inner
                };
                body.push_str(stripped);
                body.push('\n');
            }
            if body.contains("config_schema_version") {
                out.push((format!("{}:{}", path.display(), number + 1), body));
            }
        }
    }
    out
}

#[test]
fn every_documented_config_still_validates() {
    let root = repo_root();
    let mut configs: Vec<(String, String)> = Vec::new();
    for file in [
        "packaging/examples/postgres-prod.toml",
        "examples/postgres-local/volume.toml",
        "crates/maki-format/tests/data/full_config.toml",
    ] {
        let path = root.join(file);
        if let Ok(text) = std::fs::read_to_string(&path) {
            configs.push((file.to_string(), text));
        }
    }
    let mut docs = Vec::new();
    markdown_files(&root, &mut docs);
    docs.sort();
    for doc in docs {
        configs.extend(fences(&doc));
    }

    let mut refused = Vec::new();
    for (source, text) in &configs {
        let outcome = parse_config(text).map_err(|e| e.to_string()).and_then(|config| {
            config.validate().map_err(|e| e.to_string())
        });
        match outcome {
            Ok(()) => println!("OK      {source}"),
            Err(error)
                if error.contains("is not readable")
                    || error.contains("No such file") =>
            {
                println!("ENV     {source}: {error}")
            }
            Err(error) => {
                println!("REFUSED {source}: {error}");
                refused.push(format!("{source}: {error}"));
            }
        }
    }
    assert!(
        refused.is_empty(),
        "documented configurations refused:\n{}",
        refused.join("\n")
    );
}
