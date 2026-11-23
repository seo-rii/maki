//! The configuration examples in the maintained documents, and the example
//! files shipped beside them, must load with the real loader (`parse_config`
//! then `validate`), so a schema or validation change cannot leave a
//! documented example behind. The documents are `README.md`, `SPEC.md` and
//! everything under `docs/`, `examples/` and `packaging/`, except the dated
//! reports under `docs/qualification/`.
//!
//! A complete example is loaded as written. A fragment (sections of a volume
//! configuration) is merged into the quick-start example, with every change
//! its document asks of the reader spelled out in `complete`. A block of
//! another schema is listed with what it is, and an unlisted block fails, so
//! a new example cannot go unchecked.
//!
//! Unix only: the documents name Unix paths, and the remote witness TLS files
//! must be absolute on the host that validates them.
#![cfg(unix)]

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use maki_format::config::{parse_config, ConfigError};
use toml::{Table, Value};

/// The top-level keys of a volume configuration.
const VOLUME_SECTIONS: &[&str] = &[
    "volume", "crypto", "limits", "backing", "cache", "nbd", "control", "security",
];

/// TOML blocks of another schema: the document, one of the block's top-level
/// keys, and what the block is.
const OTHER_SCHEMAS: &[(&str, &str, &str)] = &[
    (
        "docs/configuration.md",
        "lvm_identity",
        "attach configuration (maki-privileged)",
    ),
    (
        "docs/remote-witness-service.md",
        "state_dir",
        "witness service configuration (maki-witness)",
    ),
    (
        "docs/remote-witness-service.md",
        "endpoints",
        "witness etcd initialization (maki-witness)",
    ),
    (
        "docs/remote-witness-service.md",
        "etcd",
        "witness service etcd store (maki-witness)",
    ),
    (
        "docs/remote-witness-service.md",
        "address",
        "witness admin client configuration (maki-witness)",
    ),
    (
        "SPEC.md",
        "token",
        "§9: literals a configuration must not hold",
    ),
];

/// Blocks that are an outline, not a TOML document: the document and the
/// block's first line.
const OUTLINES: &[(&str, &str)] = &[("SPEC.md", "Authorization = {")];

/// Shipped `.toml` examples of another schema, by file name.
const OTHER_EXAMPLE_FILES: &[&str] = &["attach.toml"];

struct Block {
    document: String,
    line: usize,
    text: String,
}

impl Block {
    fn at(&self) -> String {
        format!("{}:{}", self.document, self.line)
    }
}

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn walk(path: &Path, extension: &str, out: &mut Vec<PathBuf>) {
    if path.is_dir() {
        // Dated qualification reports record past runs, not instructions.
        if path.ends_with("docs/qualification") {
            return;
        }
        let mut entries: Vec<_> = std::fs::read_dir(path)
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        entries.sort();
        for entry in entries {
            walk(&entry, extension, out);
        }
    } else if path.extension().is_some_and(|found| found == extension) {
        out.push(path.to_path_buf());
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap()
        .to_string_lossy()
        .into_owned()
}

fn is_complete(text: &str) -> bool {
    declarations(text) > 0
}

/// Lines that open a complete volume configuration.
fn declarations(text: &str) -> usize {
    text.lines()
        .filter(|line| line.trim_start().starts_with("config_schema_version"))
        .count()
}

/// The ```` ```toml ```` blocks of one document. A block inside a list item
/// is indented with it; that indentation is removed.
fn toml_blocks(document: &str, text: &str) -> Vec<Block> {
    let mut blocks = Vec::new();
    let mut open: Option<(bool, usize, Block)> = None;
    for (index, line) in text.lines().enumerate() {
        let content = line.trim_start();
        let fence = content.strip_prefix("```");
        match (&mut open, fence) {
            (None, Some(info)) => {
                let block = Block {
                    document: document.to_string(),
                    line: index + 1,
                    text: String::new(),
                };
                open = Some((info.trim() == "toml", line.len() - content.len(), block));
            }
            (None, None) => {}
            (Some(_), Some(_)) => {
                let (toml, _, block) = open.take().unwrap();
                if toml {
                    blocks.push(block);
                }
            }
            (Some((_, indent, block)), None) => {
                let indent = (*indent).min(line.len() - content.len());
                block.text.push_str(&line[indent..]);
                block.text.push('\n');
            }
        }
    }
    assert!(open.is_none(), "{document}: unterminated code block");
    blocks
}

fn load(text: &str) -> Result<(), ConfigError> {
    parse_config(text)?.validate()
}

fn merge(into: &mut Table, from: &Table) {
    for (key, value) in from {
        match (into.get_mut(key), value) {
            (Some(Value::Table(existing)), Value::Table(new)) => merge(existing, new),
            _ => {
                into.insert(key.clone(), value.clone());
            }
        }
    }
}

fn section<'a>(table: &'a mut Table, path: &[&str]) -> Option<&'a mut Table> {
    path.iter()
        .try_fold(table, |table, key| table.get_mut(*key)?.as_table_mut())
}

fn has(table: &Table, path: &[&str]) -> bool {
    path.iter()
        .try_fold(table, |table, key| table.get(*key)?.as_table())
        .is_some()
}

/// What a fragment is completed with.
struct Completion {
    /// The quick-start guide's complete local-provider configuration.
    quickstart: Table,
    /// The small rollback-protected volume of rollback-protection.md.
    protected: Table,
    /// A file that exists, for TLS paths validation opens.
    tls_file: String,
}

/// The complete configuration a fragment belongs to: the quick-start example
/// with the fragment's sections merged over it, plus what the fragment's
/// document tells the reader to change or leaves to the deployment.
fn complete(fragment: &Table, with: &Completion) -> Table {
    let mut config = with.quickstart.clone();
    if has(fragment, &["backing", "rollback_protection"]) {
        // rollback-protection.md: "Merge these sections into a valid
        // small-volume configuration". Its local example carries the volume
        // and the reserves that the capacity of the other examples exceeds.
        merge(&mut config, &with.protected);
    }
    merge(&mut config, fragment);
    if has(&config, &["backing", "rollback_protection", "remote"]) {
        // "Replace `witness_root` with a remote section; configuring both is
        // refused."
        section(&mut config, &["backing", "rollback_protection"])
            .unwrap()
            .remove("witness_root");
    }

    // A fragment for a remote transport shows that transport's tables only.
    let crypto = section(&mut config, &["crypto"]).unwrap();
    for (name, provider) in [
        ("http", "remote-http"),
        ("websocket", "remote-websocket"),
        ("grpc", "remote-grpc"),
    ] {
        let Some(transport) = section(crypto, &[name]) else {
            continue;
        };
        // The documented certificate paths do not exist on the test host.
        if let Some(tls) = section(transport, &["tls"]) {
            for file in ["ca_file", "client_cert_file"] {
                if tls.contains_key(file) {
                    tls.insert(file.into(), Value::String(with.tls_file.clone()));
                }
            }
        }
        // SPEC §19 shows the encrypt mapping of one endpoint; decrypt has
        // the same shape.
        if !transport.contains_key("endpoint") {
            let mut endpoint = Table::new();
            endpoint.insert("name".into(), Value::String("primary".into()));
            endpoint.insert("url".into(), Value::String("https://crypto.example".into()));
            transport.insert(
                "endpoint".into(),
                Value::Array(vec![Value::Table(endpoint)]),
            );
        }
        if name == "http" && !transport.contains_key("decrypt") {
            let encrypt = transport["encrypt"].clone();
            transport.insert("decrypt".into(), encrypt);
        }
        // The quick-start example is a local provider with a local key.
        crypto.insert("provider".into(), Value::String(provider.into()));
        crypto.remove("key");
    }
    config
}

#[test]
fn documented_volume_configurations_load() {
    let root = repository();
    let mut documents = vec![root.join("README.md"), root.join("SPEC.md")];
    for directory in ["docs", "examples", "packaging"] {
        walk(&root.join(directory), "md", &mut documents);
    }
    let mut blocks = Vec::new();
    for path in &documents {
        let document = relative(&root, path);
        let text = std::fs::read_to_string(path).unwrap();
        let found = toml_blocks(&document, &text);
        // A complete configuration in a shell here-document or an untagged
        // block would not be checked below.
        assert_eq!(
            found
                .iter()
                .map(|block| declarations(&block.text))
                .sum::<usize>(),
            declarations(&text),
            "{document}: a complete configuration outside a ```toml block is not checked"
        );
        blocks.extend(found);
    }

    // Complete examples first: the fragments below are merged into one.
    let mut complete_in = BTreeSet::new();
    for block in blocks.iter().filter(|block| is_complete(&block.text)) {
        load(&block.text).unwrap_or_else(|error| panic!("{}: {error}", block.at()));
        complete_in.insert(block.document.as_str());
    }
    for document in ["SPEC.md", "docs/getting-started/quickstart.md"] {
        assert!(
            complete_in.contains(document),
            "{document}: no complete example found"
        );
    }

    let table_of = |document: &str, wanted: &dyn Fn(&Table) -> bool| -> Table {
        let mut tables = blocks
            .iter()
            .filter(|block| block.document == document)
            .filter_map(|block| block.text.parse::<Table>().ok())
            .filter(|table| wanted(table));
        let table = tables
            .next()
            .unwrap_or_else(|| panic!("{document}: example not found"));
        assert!(tables.next().is_none(), "{document}: several such examples");
        table
    };
    let tls_file = tempfile::NamedTempFile::new().unwrap();
    let with = Completion {
        quickstart: table_of("docs/getting-started/quickstart.md", &|table| {
            table.contains_key("config_schema_version")
        }),
        protected: table_of("docs/rollback-protection.md", &|table| {
            has(table, &["backing", "rollback_protection"])
                && table["backing"]["rollback_protection"]
                    .get("witness_root")
                    .is_some()
        }),
        tls_file: tls_file.path().to_str().unwrap().to_string(),
    };

    let mut listed = BTreeSet::new();
    for block in blocks.iter().filter(|block| !is_complete(&block.text)) {
        let at = block.at();
        let Ok(fragment) = block.text.parse::<Table>() else {
            let outline = OUTLINES
                .iter()
                .find(|(document, first)| {
                    *document == block.document && block.text.starts_with(first)
                })
                .unwrap_or_else(|| panic!("{at}: not TOML; correct it or list it in OUTLINES"));
            listed.insert((outline.0, outline.1));
            continue;
        };
        if fragment
            .keys()
            .any(|key| !VOLUME_SECTIONS.contains(&key.as_str()))
        {
            let other = OTHER_SCHEMAS
                .iter()
                .find(|(document, key, _)| {
                    *document == block.document && fragment.contains_key(*key)
                })
                .unwrap_or_else(|| {
                    panic!(
                        "{at}: not sections of a volume configuration; correct it or list it \
                         in OTHER_SCHEMAS"
                    )
                });
            listed.insert((other.0, other.1));
            continue;
        }
        let text = toml::to_string(&complete(&fragment, &with)).unwrap();
        load(&text).unwrap_or_else(|error| {
            panic!("{at}: merged into the quick-start example: {error}\n{text}")
        });
    }
    // Every listed exception still exists.
    for entry in OTHER_SCHEMAS
        .iter()
        .map(|(document, key, _)| (*document, *key))
        .chain(OUTLINES.iter().copied())
    {
        assert!(
            listed.contains(&entry),
            "{}: the listed block {:?} no longer exists",
            entry.0,
            entry.1
        );
    }

    let mut files = Vec::new();
    for directory in ["examples", "packaging"] {
        walk(&root.join(directory), "toml", &mut files);
    }
    let mut shipped = 0;
    for path in &files {
        let name = relative(&root, path);
        let text = std::fs::read_to_string(path).unwrap();
        if is_complete(&text) {
            load(&text).unwrap_or_else(|error| panic!("{name}: {error}"));
            shipped += 1;
        } else {
            let file = path.file_name().unwrap().to_str().unwrap();
            assert!(
                OTHER_EXAMPLE_FILES.contains(&file),
                "{name}: neither a volume configuration nor a listed example of another schema"
            );
        }
    }
    assert!(
        shipped >= 2,
        "only {shipped} shipped volume configurations found"
    );
}

/// docs/configuration.md names the byte-valued keys that are plain integers.
/// Each takes the bare number and refuses the size string every other byte
/// key accepts; the document's list and this one must stay the same.
#[test]
fn byte_keys_documented_as_plain_integers_refuse_a_size_string() {
    const INTEGER_KEYS: &[(&str, i64)] = &[
        ("volume.device_block_size", 4096),
        ("volume.crypto_unit_size", 4096),
        ("crypto.random_prefix_bytes", 0),
        ("crypto.capabilities.supported_plaintext_sizes", 4096),
        ("crypto.capabilities.max_ciphertext_size", 4384),
        ("backing.slot_alignment", 512),
        ("nbd.device_block_size", 4096),
        ("nbd.minimum_io", 4096),
        ("nbd.preferred_io", 4096),
    ];
    let root = repository();
    let guide = std::fs::read_to_string(root.join("docs/configuration.md")).unwrap();
    let start = guide
        .find("Byte sizes use values")
        .expect("byte-size paragraph");
    let paragraph = &guide[start..start + guide[start..].find("Durations use values").unwrap()];
    let documented: BTreeSet<&str> = paragraph
        .split('`')
        .skip(1)
        .step_by(2)
        .filter(|code| code.contains('.'))
        .collect();
    assert_eq!(
        documented,
        INTEGER_KEYS
            .iter()
            .map(|(key, _)| *key)
            .collect::<BTreeSet<_>>(),
        "docs/configuration.md and this test list different integer-only byte keys"
    );

    let quickstart = std::fs::read_to_string(root.join("docs/getting-started/quickstart.md"))
        .map(|text| toml_blocks("docs/getting-started/quickstart.md", &text))
        .unwrap()
        .into_iter()
        .find(|block| is_complete(&block.text))
        .expect("quick-start example")
        .text
        .parse::<Table>()
        .unwrap();
    let with = |key: &str, value: Value| {
        let mut config = quickstart.clone();
        let (parent, field) = key.rsplit_once('.').unwrap();
        let path: Vec<&str> = parent.split('.').collect();
        let list = field == "supported_plaintext_sizes";
        let value = if list {
            Value::Array(vec![value])
        } else {
            value
        };
        section(&mut config, &path)
            .unwrap()
            .insert(field.into(), value);
        toml::to_string(&config).unwrap()
    };
    for (key, bytes) in INTEGER_KEYS {
        load(&with(key, Value::Integer(*bytes))).unwrap_or_else(|error| panic!("{key}: {error}"));
        let sized = with(key, Value::String(format!("{bytes}B")));
        assert!(
            matches!(parse_config(&sized), Err(ConfigError::Parse(_))),
            "{key} accepted a size string"
        );
    }
    // A byte-size key takes the same string.
    load(&with("nbd.maximum_io", Value::String("1048576B".into()))).unwrap();
}
