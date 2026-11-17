//! A witness configuration decides who administers the authority
//! (`[[server.principals]]`), which private key the server presents
//! (`key_file`) and which authority it serves (`state_dir`, `[etcd]`);
//! a client configuration decides which server and CA a command trusts.
//! `read_config` refused a symlink and group/other write access but never
//! looked at the owner, and the owner of a file can rewrite it whatever its
//! mode: a `0644` configuration owned by an unrelated unprivileged user was
//! loaded by `serve`, `init-etcd` and `inspect` alike, so that user could
//! add their own certificate as an administrator or point the service at
//! another key or authority. A configuration must belong to root or to the
//! user the command runs as.
//!
//! Changing a file's owner, and running the binary as another user, need
//! root, so these cases skip otherwise.

#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

/// Unprivileged uids that are neither root nor this process.
const NOBODY: u32 = 65534;
const OTHER: u32 = 65533;
/// Appears only inside configuration values; no error may echo it.
const MARKER: &str = "WITNESS_CONFIG_MARKER";

// Copying the binary and spawning it from several threads at once can hand
// a forked child the copy's write descriptor (ETXTBSY); run one at a time.
static SPAWN: Mutex<()> = Mutex::new(());

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

/// One configuration loader: its arguments around the configuration path,
/// the file, and the error it reports once the file has been loaded. Every
/// later error is fixture-specific and independent of external services.
struct Loader {
    command: &'static str,
    trailing: &'static [&'static str],
    text: String,
    loaded: &'static str,
}

fn tls(table: &str) -> String {
    format!(
        "[{table}]\nca_file = \"/nonexistent/{MARKER}.ca.pem\"\n\
         cert_file = \"/nonexistent/{MARKER}.cert.pem\"\n\
         key_file = \"/nonexistent/{MARKER}.key.pem\"\n"
    )
}

fn loaders() -> Vec<Loader> {
    vec![
        // No authority: refused right after loading, before any credential.
        Loader {
            command: "serve",
            trailing: &[],
            text: format!(
                "listen = \"127.0.0.1:0\"\n[server]\ntimeout_ms = 1000\nmax_connections = 1\n\
                 principals = [{{ certificate_sha256 = \"{}\", role = \"admin\" }}]\n{}",
                "a".repeat(64),
                tls("server.tls")
            ),
            loaded: "serve requires exactly one local or etcd authority",
        },
        // The command's identity differs from the pin: refused before TLS.
        Loader {
            command: "init-etcd",
            trailing: &["11111111-1111-1111-1111-111111111111"],
            text: format!(
                "cluster_id = \"42\"\nstorage_identity = \"22222222-2222-2222-2222-222222222222\"\n\
                 key = \"/maki/witness/{MARKER}\"\ntimeout_ms = 1000\n\
                 [[endpoints]]\naddress = \"127.0.0.1:1\"\nserver_name = \"localhost\"\n{}",
                tls("tls")
            ),
            loaded: "initialization identity differs from configured pin",
        },
        // An out-of-range deadline: refused before TLS or any connection.
        Loader {
            command: "inspect",
            trailing: &[],
            text: format!(
                "address = \"127.0.0.1:1\"\nserver_name = \"localhost\"\ntimeout_ms = 0\n{}",
                tls("tls")
            ),
            loaded: "witness timeout_ms must be in 1..=60000",
        },
    ]
}

struct Fixture {
    dir: tempfile::TempDir,
    binary: PathBuf,
}

impl Fixture {
    /// A directory every user can search, holding a copy of the binary that
    /// every user can run (the build tree may sit below a private home).
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        let binary = dir.path().join("maki-witness");
        std::fs::copy(env!("CARGO_BIN_EXE_maki-witness"), &binary).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self { dir, binary }
    }

    fn write(&self, loader: &Loader, owner: u32, mode: u32) -> PathBuf {
        let path = self.dir.path().join(format!("{}.toml", loader.command));
        let _ = std::fs::remove_file(&path);
        std::fs::write(&path, &loader.text).unwrap();
        std::os::unix::fs::chown(&path, Some(owner), Some(owner)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Write the file as `owner` with `mode` and run the loader as `user`,
    /// or as this process when `None`: (success, stderr, description).
    fn run(
        &self,
        loader: &Loader,
        owner: u32,
        mode: u32,
        user: Option<u32>,
    ) -> (bool, String, String) {
        let config = self.write(loader, owner, mode);
        let mut command = Command::new(&self.binary);
        command
            .arg(loader.command)
            .arg(&config)
            .args(loader.trailing);
        if let Some(user) = user {
            command.uid(user).gid(user);
        }
        let output = command.output().unwrap();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        let what = format!(
            "{} as {user:?}, owner {owner}, mode {mode:o}",
            loader.command
        );
        (output.status.success(), stderr, what)
    }

    fn assert_loaded(&self, loader: &Loader, owner: u32, mode: u32, user: Option<u32>) {
        let (success, stderr, what) = self.run(loader, owner, mode, user);
        assert!(!success, "{what}: unexpected success");
        assert!(stderr.contains(loader.loaded), "{what}: {stderr}");
    }

    fn assert_refused(&self, loader: &Loader, owner: u32, mode: u32, user: Option<u32>) {
        let (success, stderr, what) = self.run(loader, owner, mode, user);
        assert!(
            !success,
            "{what}: a configuration owned by uid {owner} was accepted"
        );
        assert!(
            stderr.contains(&format!("configuration is owned by uid {owner}")),
            "{what}: {stderr}"
        );
        assert!(!stderr.contains(loader.loaded), "{what}: loaded: {stderr}");
        assert!(!stderr.contains(MARKER), "{what}: content echoed: {stderr}");
    }
}

#[test]
fn a_configuration_owned_by_another_user_is_refused_by_every_loader() {
    if !is_root() {
        eprintln!("needs root to chown the fixture and switch users; skipping");
        return;
    }
    let _serial = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    for loader in loaders() {
        // The owner can make any mode writable again, so none is safe.
        for mode in [0o644, 0o600, 0o400] {
            fixture.assert_refused(&loader, NOBODY, mode, None);
        }
        // An unprivileged user can open another user's file only when it
        // grants read access to others; then the owner check refuses it.
        for mode in [0o644, 0o444] {
            fixture.assert_refused(&loader, OTHER, mode, Some(NOBODY));
        }
    }
}

#[test]
fn root_owned_and_own_configurations_still_load() {
    if !is_root() {
        eprintln!("needs root to chown the fixture and switch users; skipping");
        return;
    }
    let _serial = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    let fixture = Fixture::new();
    for loader in loaders() {
        // A root-owned file, readable by the service user, is the usual
        // layout; a service user may also load a file it owns. Group and
        // other read access stays allowed: a configuration holds no secret.
        fixture.assert_loaded(&loader, 0, 0o644, None);
        fixture.assert_loaded(&loader, 0, 0o644, Some(NOBODY));
        fixture.assert_loaded(&loader, NOBODY, 0o600, Some(NOBODY));
        fixture.assert_loaded(&loader, NOBODY, 0o644, Some(NOBODY));
    }
}
