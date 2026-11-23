//! A volume configuration decides where plaintext goes: the crypto provider
//! and its endpoints, TLS trust, credential references, the backing root and
//! the remote witness. Every `maki` command read it with `read_to_string`,
//! so a file the group or others could write, a file another user owns (its
//! owner can rewrite it whatever its mode), a symlink and a file with a
//! second hard link (through either, a user who controls some directory can
//! substitute a file of their choosing) were loaded like the operator's
//! own. `volume create` and the remote `volume` commands then contact the
//! endpoints and the witness that file names, with the credentials it
//! references; the control commands connect to the socket it names. Each
//! loader must refuse such a file before parsing it, naming the problem,
//! while a root-owned `0640` file (SPEC 8's `root:maki`, which the daemon
//! user reads through its group) and the user's own `0600`/`0644` file
//! still load.
//!
//! Changing a file's owner, and running the CLI as another user, need root;
//! those cases skip otherwise.

#![cfg(unix)]

#[path = "support/shared_dir.rs"]
mod shared_dir;

use std::os::unix::fs::PermissionsExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

/// Unprivileged ids that are neither root nor this process.
const NOBODY: u32 = 65534;
const OTHER: u32 = 65533;

/// Stands for the configuration path in a loader's arguments.
const CONFIG: &str = "<config>";

/// The fixture parses but fails validation on its name; the control
/// commands only parse it and then fail to reach its socket. Either error
/// proves that the file was read and handed to the parser.
const VALIDATED: &str = "volume name \"-config-loaded\"";
const SOCKET: &str = "loaded-marker.sock";

/// Every command that loads a volume configuration, through each code path,
/// and the error it reports once it has read the file.
const LOADERS: [(&[&str], &str); 5] = [
    (&["volume", "create", CONFIG], VALIDATED),
    (&["volume", "inspect", CONFIG], VALIDATED),
    (&["volume", "witness", CONFIG], VALIDATED),
    (&["check", CONFIG], VALIDATED),
    (&["status", CONFIG], SOCKET),
];

// Copying the binary and spawning it from several threads at once can hand
// a forked child the copy's write descriptor (ETXTBSY); run one at a time.
static SPAWN: Mutex<()> = Mutex::new(());

fn is_root() -> bool {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() == 0 }
}

struct Fixture {
    dir: tempfile::TempDir,
    binary: PathBuf,
    /// Why other users cannot reach `dir`; the cases that run the CLI as
    /// another user skip then.
    private: Option<String>,
}

impl Fixture {
    /// A directory every user can reach, holding a copy of the binary that
    /// every user can run (the build tree may sit below a private home, and
    /// so may `TMPDIR`). Where no such directory can be made, the fixture
    /// is private to this user.
    fn new() -> Self {
        let (dir, private) = match shared_dir::tempdir() {
            Ok(dir) => (dir, None),
            Err(reason) => (tempfile::tempdir().unwrap(), Some(reason)),
        };
        let binary = dir.path().join("maki");
        std::fs::copy(env!("CARGO_BIN_EXE_maki"), &binary).unwrap();
        std::fs::set_permissions(&binary, std::fs::Permissions::from_mode(0o755)).unwrap();
        Self {
            dir,
            binary,
            private,
        }
    }

    /// Whether `test` must skip its cases that run as another user; says so.
    fn skips_other_users(&self, test: &str) -> bool {
        if let Some(reason) = &self.private {
            eprintln!("{test}: skipped the cases that run as another user: {reason}");
        }
        self.private.is_some()
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    /// Write the fixture under `name` with `mode`, owned by this process.
    fn write(&self, name: &str, mode: u32) -> PathBuf {
        let path = self.path(name);
        let _ = std::fs::remove_file(&path);
        std::fs::write(
            &path,
            format!(
                "config_schema_version = 1\n[volume]\nname = \"-config-loaded\"\n\
                 max_virtual_size = \"1MiB\"\n[backing]\nroot = {:?}\n[crypto]\n\
                 provider = \"local-aes-gcm-siv\"\ncrypto_compatibility_id = \"test\"\n\
                 key = {{ source = \"env\", name = \"unused\" }}\n[crypto.capabilities]\n\
                 supported_plaintext_sizes = [4096]\nmax_ciphertext_size = 4384\n[control]\nsocket = {:?}\n",
                self.path("volume").to_str().unwrap(),
                self.path(SOCKET).to_str().unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(mode)).unwrap();
        path
    }

    /// Write the fixture owned by `owner`:`group` with `mode`.
    fn write_owned(&self, name: &str, owner: u32, group: u32, mode: u32) -> PathBuf {
        let path = self.write(name, mode);
        std::os::unix::fs::chown(&path, Some(owner), Some(group)).unwrap();
        path
    }

    /// Run every loader on `config` as `user` (`None`: this process) and
    /// return (arguments, success, stderr, the loader's "loaded" marker).
    fn run(&self, config: &Path, user: Option<u32>) -> Vec<(String, bool, String, &'static str)> {
        let _serial = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
        LOADERS
            .iter()
            .map(|(args, loaded)| {
                let mut command = Command::new(&self.binary);
                for arg in *args {
                    if *arg == CONFIG {
                        command.arg(config);
                    } else {
                        command.arg(arg);
                    }
                }
                if let Some(user) = user {
                    command.uid(user).gid(user);
                }
                let output = command.output().unwrap();
                (
                    format!("maki {} as {user:?}", args.join(" ")),
                    output.status.success(),
                    String::from_utf8_lossy(&output.stderr).into_owned(),
                    *loaded,
                )
            })
            .collect()
    }

    fn assert_loaded(&self, config: &Path, user: Option<u32>, what: &str) {
        for (command, success, stderr, loaded) in self.run(config, user) {
            assert!(!success, "{what}: {command}: unexpected success");
            assert!(
                stderr.contains(loaded),
                "{what}: {command}: not loaded: {stderr}"
            );
        }
    }

    fn assert_refused(&self, config: &Path, user: Option<u32>, problem: &str, what: &str) {
        for (command, success, stderr, loaded) in self.run(config, user) {
            assert!(!success, "{what}: {command}: unexpected success");
            assert!(
                !stderr.contains(loaded),
                "{what}: {command}: loaded: {stderr}"
            );
            assert!(
                stderr.contains(problem),
                "{what}: {command}: expected {problem:?}: {stderr}"
            );
            assert!(
                stderr.contains(config.to_str().unwrap()),
                "{what}: {command}: the error does not name the file: {stderr}"
            );
        }
    }
}

fn new_fixture() -> Fixture {
    let _serial = SPAWN.lock().unwrap_or_else(|e| e.into_inner());
    Fixture::new()
}

#[test]
fn group_or_world_writable_configurations_are_refused_by_every_loader() {
    let fixture = new_fixture();
    for mode in [0o620, 0o664, 0o602, 0o666] {
        let config = fixture.write(&format!("mode-{mode:o}.toml"), mode);
        fixture.assert_refused(
            &config,
            None,
            "writable by the group or by others",
            &format!("mode {mode:o}"),
        );
    }
}

#[test]
fn symlinked_and_hardlinked_configurations_are_refused_by_every_loader() {
    let fixture = new_fixture();
    let target = fixture.write("target.toml", 0o640);
    fixture.assert_loaded(&target, None, "symlink target");
    let link = fixture.path("link.toml");
    std::os::unix::fs::symlink(&target, &link).unwrap();
    fixture.assert_refused(&link, None, "symbolic link", "symlink");

    let second = fixture.path("second.toml");
    std::fs::hard_link(&target, &second).unwrap();
    fixture.assert_refused(&target, None, "hard links", "first of two links");
    fixture.assert_refused(&second, None, "hard links", "second of two links");
}

#[test]
fn a_configuration_owned_by_another_user_is_refused_by_every_loader() {
    if !is_root() {
        eprintln!("needs root to chown the fixture and switch users; skipping");
        return;
    }
    let fixture = new_fixture();
    // The owner can make any mode writable again, so none is safe: root
    // refuses the daemon user's file as well as a stranger's.
    for mode in [0o644, 0o640, 0o600] {
        let config = fixture.write_owned("foreign.toml", NOBODY, NOBODY, mode);
        fixture.assert_refused(
            &config,
            None,
            &format!("owned by uid {NOBODY}"),
            &format!("root loading owner {NOBODY}, mode {mode:o}"),
        );
    }
    if fixture.skips_other_users("a_configuration_owned_by_another_user_is_refused_by_every_loader")
    {
        return;
    }
    // An unprivileged user can open another user's file only when it grants
    // read access to others; the owner check then refuses it.
    let config = fixture.write_owned("stranger.toml", OTHER, OTHER, 0o644);
    fixture.assert_refused(
        &config,
        Some(NOBODY),
        &format!("owned by uid {OTHER}"),
        "a stranger's file",
    );
}

#[test]
fn root_owned_and_own_configurations_still_load_in_every_loader() {
    let fixture = new_fixture();
    // Group and other read stay allowed: a configuration holds no secret.
    for mode in [0o600, 0o640, 0o644] {
        let config = fixture.write(&format!("own-{mode:o}.toml"), mode);
        fixture.assert_loaded(&config, None, &format!("own file, mode {mode:o}"));
    }
    if !is_root() {
        eprintln!("needs root to chown the fixture and switch users; skipping the rest");
        return;
    }
    if fixture.skips_other_users("root_owned_and_own_configurations_still_load_in_every_loader") {
        return;
    }
    // SPEC 8: root:maki 0640, read by the daemon user through its group.
    let config = fixture.write_owned("root-group.toml", 0, NOBODY, 0o640);
    fixture.assert_loaded(&config, Some(NOBODY), "root:group 0640 read by the group");
    // A service user may load a file it owns.
    for mode in [0o600, 0o644] {
        let config = fixture.write_owned("service-own.toml", NOBODY, NOBODY, mode);
        fixture.assert_loaded(
            &config,
            Some(NOBODY),
            &format!("the user's own file, mode {mode:o}"),
        );
    }
}
