//! Attach refuses a configuration that does not match a remote-protected
//! volume before it claims a writer at the authority.
//!
//! Attach compared the configuration with the superblock that recovery
//! selects, after opening the backing, and opening a remote-protected
//! backing to write claims a writer at the authority (`Action::Claim`),
//! activates a namespace of its own with a copy of the current generation
//! and releases it again when the refusal drops it. A configuration that
//! attach then refused (another compatibility id, another geometry, another
//! capacity) still raised the authority's fence, replaced its session and
//! current namespace, copied every page of the generation there and
//! recovered the volume in it, which advanced the authority's generation:
//! each refusal sent `claim`, `activate`, `advance` several times and
//! `release`, besides its inspections. Attach now
//! reads the superblock of the authority's current generation where the
//! claim would be sent, under the root's operation lock and once the
//! generation authenticates, and refuses before the claim: the authority is
//! sent its one inspection and nothing else, and its record and the root are
//! unchanged. A matching configuration still claims, as before. A remote
//! provider built on its own (`build_provider_with_endpoints`) recovers the
//! volume to probe its endpoints against it, and compares the same way. The
//! authority here is a real TLS witness server whose handler records the
//! action of every request.
#![cfg(target_os = "linux")]

#[path = "support/private_dir.rs"]
mod private_dir;

use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use maki_backing::remote_witness::{Action, Phase, Record, Request, StateStore};
use maki_core::engine::AttachError;
use maki_nbdkit::daemon::{
    attach_from_config, build_provider_with_endpoints, create_volume_from_config_str,
    parse_and_validate, DaemonError,
};
use maki_witness::{certificate_fingerprint, Principal, Role, Server, ServerOptions, TlsFiles};

fn files(root: &Path, name: &str, key: &rcgen::CertifiedKey, ca: &str) -> TlsFiles {
    let ca_file = root.join(format!("{name}.ca.pem"));
    let cert_file = root.join(format!("{name}.cert.pem"));
    let key_file = root.join(format!("{name}.key.pem"));
    std::fs::write(&ca_file, ca).unwrap();
    std::fs::write(&cert_file, key.cert.pem()).unwrap();
    std::fs::write(&key_file, key.key_pair.serialize_pem()).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&key_file, std::fs::Permissions::from_mode(0o600)).unwrap();
    TlsFiles {
        ca_file,
        cert_file,
        key_file,
    }
}

fn action_name(action: &Action) -> &'static str {
    match action {
        Action::Inspect => "inspect",
        Action::Claim => "claim",
        Action::Takeover => "takeover",
        Action::RecoverEnrollment => "recover-enrollment",
        Action::ClaimRestore { .. } => "claim-restore",
        Action::Activate { .. } => "activate",
        Action::Advance { .. } => "advance",
        Action::Release => "release",
    }
}

/// A TLS witness server over a local state store, recording the action of
/// every request it is sent, and a volume configuration that uses it.
struct Authority {
    address: std::net::SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    state: Arc<Mutex<StateStore>>,
    actions: Arc<Mutex<Vec<&'static str>>>,
    _witness: tempfile::TempDir,
    tls: tempfile::TempDir,
    root: tempfile::TempDir,
}

impl Drop for Authority {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(self.address);
        if let Some(worker) = self.worker.take() {
            worker.join().unwrap();
        }
    }
}

impl Authority {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let witness = private_dir::tempdir().unwrap();
        let tls = tempfile::tempdir().unwrap();
        let server_key = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let writer_key = rcgen::generate_simple_self_signed(vec!["writer".into()]).unwrap();
        let server_files = files(tls.path(), "server", &server_key, &writer_key.cert.pem());
        files(tls.path(), "writer", &writer_key, &server_key.cert.pem());
        let server = Server::new(ServerOptions {
            tls: server_files,
            principals: vec![Principal {
                certificate_sha256: certificate_fingerprint(writer_key.cert.der()),
                role: Role::Writer,
            }],
            timeout_ms: 2000,
            max_connections: 2,
        })
        .unwrap();
        let state = Arc::new(Mutex::new(
            StateStore::create(witness.path(), [9; 16]).unwrap(),
        ));
        let actions = Arc::new(Mutex::new(Vec::new()));
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let worker = std::thread::spawn({
            let (state, actions, stop) = (state.clone(), actions.clone(), stop.clone());
            move || {
                let handler = move |role, value: &[u8]| {
                    let request: Request =
                        serde_json::from_slice(value).map_err(std::io::Error::other)?;
                    actions.lock().unwrap().push(action_name(&request.action));
                    let record = state.lock().unwrap().handle(role, &request)?;
                    serde_json::to_value(record).map_err(std::io::Error::other)
                };
                for socket in listener.incoming() {
                    if stop.load(Ordering::SeqCst) {
                        break;
                    }
                    let _ = server.handle_connection(socket.unwrap(), &handler);
                }
            }
        });
        Self {
            address,
            stop,
            worker: Some(worker),
            state,
            actions,
            _witness: witness,
            tls,
            root,
        }
    }

    /// The configuration of the volume with the fake provider, with
    /// `replace` applied to its text.
    fn config(&self, replace: (&str, &str)) -> String {
        self.config_with(FAKE, replace)
    }

    /// The configuration of the volume with the `crypto` section, with
    /// `replace` applied to its text.
    fn config_with(&self, crypto: &str, replace: (&str, &str)) -> String {
        let tls = |name: &str| {
            self.tls
                .path()
                .join(format!("writer.{name}.pem"))
                .display()
                .to_string()
        };
        let text = format!(
            r#"config_schema_version=1
[volume]
name="remote-compare"
max_virtual_size="16MiB"
shard_logical_size="8MiB"
{crypto}[backing]
root={:?}
journal_segment_size="64KiB"
journal_max_bytes="1MiB"
checkpoint_reserve_bytes="64KiB"
journal_emergency_reserve_bytes="64KiB"
[backing.rollback_protection]
capacity="16MiB"
[backing.rollback_protection.remote]
address="{}"
server_name="localhost"
timeout_ms=2000
ca_file={:?}
client_cert_file={:?}
client_key_file={:?}
[nbd]
maximum_io="64KiB"
"#,
            self.root.path().display().to_string(),
            self.address,
            tls("ca"),
            tls("cert"),
            tls("key"),
        );
        assert!(text.contains(replace.0), "{replace:?}");
        text.replace(replace.0, replace.1)
    }

    /// The authority's record, read from its store without a request.
    fn record(&self) -> Record {
        self.state
            .lock()
            .unwrap()
            .handle(
                Role::Writer,
                &Request {
                    operation_id: *uuid::Uuid::new_v4().as_bytes(),
                    expected: None,
                    action: Action::Inspect,
                    authorization: None,
                },
            )
            .unwrap()
    }

    /// Forget the actions sent so far and return them.
    fn take_actions(&self) -> Vec<&'static str> {
        std::mem::take(&mut *self.actions.lock().unwrap())
    }

    /// Every entry of the backing root, with its bytes if it is a file.
    fn tree(&self) -> Vec<(PathBuf, Option<Vec<u8>>)> {
        let mut entries = Vec::new();
        let mut pending = vec![self.root.path().to_path_buf()];
        while let Some(path) = pending.pop() {
            if path.is_dir() {
                for entry in std::fs::read_dir(&path).unwrap() {
                    pending.push(entry.unwrap().path());
                }
                entries.push((path, None));
            } else {
                let bytes = std::fs::read(&path).unwrap();
                entries.push((path, Some(bytes)));
            }
        }
        entries.sort();
        entries
    }
}

const FAKE: &str = r#"[crypto]
provider="fake"
crypto_compatibility_id="v1"
[crypto.capabilities]
supported_plaintext_sizes=[4096]
max_ciphertext_size=4384
"#;

/// A remote provider whose one endpoint nothing listens on: nothing may be
/// sent to it for a configuration the volume refuses.
const REMOTE_HTTP: &str = r#"[crypto]
provider="remote-http"
crypto_compatibility_id="v1"
availability_policy="bounded-error"
max_operation_time="1s"
[crypto.capabilities]
supported_plaintext_sizes=[4096]
max_ciphertext_size=4384
stateless=true
[crypto.batch]
max_items=1
target_items=1
max_bytes=4384
target_bytes=4384
max_wait="0ms"
[crypto.http]
max_response_bytes=8192
timeout="1s"
[[crypto.http.endpoint]]
name="only"
url="http://127.0.0.1:1"
[crypto.http.encrypt]
path="/encrypt"
[crypto.http.decrypt]
path="/decrypt"
[cache]
mode="off"
"#;

/// The volume, created and then written through the engine once, released.
async fn volume() -> Authority {
    let authority = Authority::new();
    let config = authority.config(("", ""));
    create_volume_from_config_str(&config).unwrap();
    let engine = attach_from_config(&parse_and_validate(&config).unwrap())
        .await
        .unwrap();
    engine.write(0, &[0x5a; 4096], true).await.unwrap();
    engine.checkpoint().await.unwrap();
    drop(engine);
    assert_eq!(authority.record().phase, Phase::Released);
    authority
}

/// The configurations that attach refuses for this volume, each with what
/// the refusal says.
const MISMATCHES: [((&str, &str), &str); 3] = [
    (
        (
            r#"crypto_compatibility_id="v1""#,
            r#"crypto_compatibility_id="v2""#,
        ),
        r#"volume was created with compatibility id "v1", configuration says "v2""#,
    ),
    (
        (
            r#"shard_logical_size="8MiB""#,
            r#"shard_logical_size="4MiB""#,
        ),
        "volume geometry shard_logical_size mismatch: configuration 4194304, stored 8388608",
    ),
    (
        (r#"capacity="16MiB""#, r#"capacity="32MiB""#),
        "protected backing capacity mismatch: configuration 33554432, stored 16777216",
    ),
];

#[tokio::test]
async fn a_mismatched_configuration_is_refused_before_a_writer_is_claimed() {
    let authority = volume().await;
    for (replace, expected) in MISMATCHES {
        let config = parse_and_validate(&authority.config(replace)).unwrap();
        let (record, tree) = (authority.record(), authority.tree());
        authority.take_actions();
        let error = match attach_from_config(&config).await {
            Ok(_) => panic!("attach accepted {replace:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{replace:?}: {error}");
        if replace.0.starts_with("crypto_compatibility_id") {
            assert!(
                matches!(error, DaemonError::Attach(AttachError::IdentityMismatch(_))),
                "{error:?}"
            );
        } else {
            assert!(matches!(error, DaemonError::Unsupported(_)), "{error:?}");
        }
        assert_eq!(
            authority.take_actions(),
            ["inspect"],
            "{replace:?}: the authority was sent more than the open's inspection"
        );
        assert_eq!(authority.record(), record, "{replace:?}");
        assert_eq!(authority.tree(), tree, "{replace:?}: the root changed");
    }
    // A matching configuration is claimed as before, and reads what was
    // written.
    let config = parse_and_validate(&authority.config(("", ""))).unwrap();
    let engine = attach_from_config(&config).await.unwrap();
    let actions = authority.take_actions();
    assert_eq!(
        actions[..3],
        ["inspect", "claim", "activate"],
        "{actions:?}"
    );
    assert_eq!(authority.record().phase, Phase::Active);
    assert_eq!(engine.read(0, 4096).await.unwrap(), [0x5a; 4096]);
}

/// While a writer is active the claim is refused anyway, and the
/// comparison does not run: a second attach, of a configuration that does
/// not match, is refused by the claim as it was.
#[tokio::test]
async fn an_occupied_authority_keeps_the_claim_refusal() {
    let authority = volume().await;
    let config = parse_and_validate(&authority.config(("", ""))).unwrap();
    let engine = attach_from_config(&config).await.unwrap();
    let (replace, _) = MISMATCHES[0];
    let mismatched = parse_and_validate(&authority.config(replace)).unwrap();
    authority.take_actions();
    let error = match attach_from_config(&mismatched).await {
        Ok(_) => panic!("a second writer attached"),
        Err(error) => error,
    };
    assert!(
        !error.to_string().contains("compatibility id"),
        "the comparison ran against an occupied authority: {error}"
    );
    // The active writer may ask the authority meanwhile.
    let actions = authority.take_actions();
    let sent: Vec<_> = actions
        .iter()
        .filter(|action| **action != "inspect")
        .collect();
    assert_eq!(sent, [&"claim"], "{actions:?}");
    assert_eq!(authority.record().phase, Phase::Active);
    drop(engine);
}

/// A remote provider built on its own recovers the volume to probe its
/// endpoints against it, after the same comparison: a configuration the
/// volume refuses is refused before the claim there too, and its endpoint
/// is never asked (nothing listens on it).
#[tokio::test]
async fn a_remote_provider_built_on_its_own_compares_before_the_claim_too() {
    let authority = Authority::new();
    create_volume_from_config_str(&authority.config_with(REMOTE_HTTP, ("", ""))).unwrap();
    for (replace, expected) in MISMATCHES {
        let config = parse_and_validate(&authority.config_with(REMOTE_HTTP, replace)).unwrap();
        let (record, tree) = (authority.record(), authority.tree());
        authority.take_actions();
        let error = match build_provider_with_endpoints(&config).await {
            Ok(_) => panic!("built a provider for {replace:?}"),
            Err(error) => error,
        };
        assert!(error.to_string().contains(expected), "{replace:?}: {error}");
        assert_eq!(authority.take_actions(), ["inspect"], "{replace:?}");
        assert_eq!(authority.record(), record, "{replace:?}");
        assert_eq!(authority.tree(), tree, "{replace:?}: the root changed");
    }
}

/// A superblock page that does not authenticate is refused before the
/// claim too, where the comparison reads it: the claim was granted and the
/// copy into the new namespace then failed on the page, which left the
/// authority claimed and the root holding a namespace that nothing
/// activated.
#[tokio::test]
async fn a_superblock_page_that_does_not_authenticate_is_refused_before_the_claim() {
    let authority = volume().await;
    let record = authority.record();
    let current = record.current.as_ref().unwrap();
    let namespace = authority.root.path().join(&current.namespace);
    let manifest = (0..2)
        .filter_map(|index| {
            let bytes = std::fs::read(namespace.join(format!("rollback.manifest.{index}"))).ok()?;
            let len = u64::from_le_bytes(bytes.get(..8)?.try_into().unwrap()) as usize;
            serde_json::from_slice::<serde_json::Value>(bytes.get(8..8 + len)?).ok()
        })
        .find(|manifest| manifest["generation"] == current.anchor.generation)
        .expect("the current generation's manifest");
    let id = manifest["entries"]["superblock.a"]["File"]
        .as_u64()
        .unwrap();
    let slot = manifest["files"][id.to_string()]["pages"]["0"]["slot"]
        .as_u64()
        .unwrap();
    let arena = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(namespace.join("rollback.arena"))
        .unwrap();
    use std::os::unix::fs::FileExt;
    let mut byte = [0];
    arena.read_exact_at(&mut byte, slot * 4096 + 17).unwrap();
    arena
        .write_all_at(&[byte[0] ^ 1], slot * 4096 + 17)
        .unwrap();
    drop(arena);
    let config = parse_and_validate(&authority.config(("", ""))).unwrap();
    let tree = authority.tree();
    authority.take_actions();
    let error = match attach_from_config(&config).await {
        Ok(_) => panic!("attached a volume whose superblock page does not authenticate"),
        Err(error) => error,
    };
    assert!(
        error
            .to_string()
            .contains("rollback arena page authentication failed"),
        "{error}"
    );
    assert_eq!(authority.take_actions(), ["inspect"]);
    assert_eq!(authority.record(), record);
    assert_eq!(authority.tree(), tree, "the root changed");
}
