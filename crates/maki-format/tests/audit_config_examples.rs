//! Audit (config-format): every shipped or documented complete configuration
//! must parse and validate with the current schema, and documented snippets
//! must validate once merged into a complete configuration as the prose says.

use maki_format::config::parse_config;

const SPEC: &str = include_str!("../../../SPEC.md");
const QUICKSTART: &str = include_str!("../../../docs/getting-started/quickstart.md");
const CONFIGURATION: &str = include_str!("../../../docs/configuration.md");
const PREFIX_DOC: &str = include_str!("../../../docs/random-plaintext-prefix.md");
const ROLLBACK_DOC: &str = include_str!("../../../docs/rollback-protection.md");
const WITNESS_DOC: &str = include_str!("../../../docs/remote-witness-service.md");
const POSTGRES_LOCAL: &str = include_str!("../../../examples/postgres-local/volume.toml");
const POSTGRES_PROD: &str = include_str!("../../../packaging/examples/postgres-prod.toml");

/// Every ```toml fence of a Markdown document, in order.
fn toml_fences(markdown: &str) -> Vec<String> {
    let mut fences = Vec::new();
    let mut current: Option<String> = None;
    for line in markdown.lines() {
        let trimmed = line.trim_start();
        match &mut current {
            None if trimmed.starts_with("```toml") => current = Some(String::new()),
            Some(body) if trimmed.starts_with("```") => {
                fences.push(std::mem::take(body));
                current = None;
            }
            Some(body) => {
                body.push_str(line);
                body.push('\n');
            }
            None => {}
        }
    }
    fences
}

fn complete_fences(markdown: &str) -> Vec<String> {
    toml_fences(markdown)
        .into_iter()
        .filter(|f| f.contains("config_schema_version"))
        .collect()
}

fn check(name: &str, raw: &str) -> Result<(), String> {
    let config = parse_config(raw).map_err(|e| format!("{name}: {e}"))?;
    config.validate().map_err(|e| format!("{name}: {e}"))
}

#[test]
fn spec_default_configuration_example_validates() {
    let fences = complete_fences(SPEC);
    assert!(!fences.is_empty(), "SPEC §57 example not found");
    for (i, fence) in fences.iter().enumerate() {
        check(&format!("SPEC.md complete fence {i}"), fence).unwrap();
    }
}

#[test]
fn quickstart_configuration_validates() {
    let fences = complete_fences(QUICKSTART);
    assert!(!fences.is_empty());
    for (i, fence) in fences.iter().enumerate() {
        check(&format!("quickstart fence {i}"), fence).unwrap();
    }
}

#[test]
fn shipped_example_files_validate() {
    check("examples/postgres-local/volume.toml", POSTGRES_LOCAL).unwrap();
    check("packaging/examples/postgres-prod.toml", POSTGRES_PROD).unwrap();
}

/// Replace whole `[table]` sections of `base` with the same-named sections
/// of `snippet` and add new ones; keys of a replaced table are merged.
fn merge(base: &str, snippet: &str) -> String {
    // Parse both as TOML tables and merge recursively, then re-serialize.
    let mut base: toml::Table = base.parse().unwrap();
    let snippet: toml::Table = snippet.parse().unwrap();
    fn merge_into(dst: &mut toml::Table, src: &toml::Table) {
        for (k, v) in src {
            match (dst.get_mut(k), v) {
                (Some(toml::Value::Table(d)), toml::Value::Table(s)) => merge_into(d, s),
                _ => {
                    dst.insert(k.clone(), v.clone());
                }
            }
        }
    }
    merge_into(&mut base, &snippet);
    toml::to_string(&base).unwrap()
}

#[test]
fn random_prefix_snippet_validates_when_merged_into_quickstart() {
    let base = complete_fences(QUICKSTART).remove(0);
    let snippet = toml_fences(PREFIX_DOC)
        .into_iter()
        .find(|f| f.contains("random_prefix_bytes"))
        .unwrap();
    check("random-plaintext-prefix.md", &merge(&base, &snippet)).unwrap();
}

#[test]
fn rollback_local_snippet_validates_when_merged_into_quickstart() {
    let base = complete_fences(QUICKSTART).remove(0);
    let snippet = toml_fences(ROLLBACK_DOC)
        .into_iter()
        .find(|f| f.contains("witness_root"))
        .unwrap();
    check("rollback-protection.md local", &merge(&base, &snippet)).unwrap();
}

#[test]
fn rollback_remote_snippets_validate_when_merged() {
    let base = complete_fences(QUICKSTART).remove(0);
    let local = toml_fences(ROLLBACK_DOC)
        .into_iter()
        .find(|f| f.contains("witness_root"))
        .unwrap();
    // "Replace witness_root with a remote section".
    let local = local.replace("witness_root = \"/mnt/maki-witness/protected\"\n", "");
    let merged = merge(&base, &local);
    for (name, doc) in [
        ("rollback-protection.md remote", ROLLBACK_DOC),
        ("remote-witness-service.md", WITNESS_DOC),
        ("configuration.md", CONFIGURATION),
    ] {
        for fence in toml_fences(doc)
            .into_iter()
            .filter(|f| f.contains("[backing.rollback_protection.remote]"))
        {
            check(name, &merge(&merged, &fence)).unwrap();
        }
    }
}

#[test]
fn memory_budget_snippet_validates_when_merged() {
    let base = complete_fences(QUICKSTART).remove(0);
    let snippet = toml_fences(CONFIGURATION)
        .into_iter()
        .find(|f| f.contains("[security.memory_budget]"))
        .unwrap();
    check("configuration.md memory budget", &merge(&base, &snippet)).unwrap();
}
