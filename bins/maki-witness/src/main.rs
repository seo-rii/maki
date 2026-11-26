//! Local or quorum-backed witness process. Initialization is always explicit.

// Output goes through `diagnostic!` and the stdout helpers below: the
// `print!` family panics when a write fails (a closed pipe, a full disk),
// which replaces the exit status with 101.
#![deny(clippy::print_stdout, clippy::print_stderr)]
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;

use maki_backing::remote_witness::{Action, Record, Request, Role, Rpc, StateStore};
use maki_witness::etcd::{EtcdOptions, EtcdStore};
use maki_witness::{
    certificate_file_fingerprint, state_handler, Client, ClientOptions, Server, ServerOptions,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use uuid::Uuid;

const HELP: &str = "maki-witness init STATE_DIRECTORY VOLUME_UUID\nmaki-witness init-etcd ETCD_CONFIG.toml VOLUME_UUID\nmaki-witness serve SERVER_CONFIG.toml\nmaki-witness inspect CLIENT_CONFIG.toml\nmaki-witness fingerprint CERTIFICATE.pem\nmaki-witness --help | --version\n\ninit and init-etcd refuse existing state; serve never initializes missing state.\nserve requires exactly one state_dir or pinned etcd quorum configuration.\nTLS 1.3 and certificate allow-list authentication are mandatory.\n";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

/// `eprintln!` that cannot panic. The macro panics when the write fails,
/// and stderr can be a pipe whose reader has gone: the panic would replace
/// the command's exit status with 101. A diagnostic that cannot be
/// delivered is dropped instead.
macro_rules! diagnostic {
    ($($arg:tt)*) => {{
        use std::io::Write as _;
        let _ = writeln!(std::io::stderr().lock(), $($arg)*);
    }};
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    #[serde(default)]
    state_dir: Option<PathBuf>,
    #[serde(default)]
    etcd: Option<EtcdOptions>,
    listen: SocketAddr,
    server: ServerOptions,
}

fn read_config<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NONBLOCK | libc::O_NOFOLLOW);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration must be a regular file at most 64 KiB",
        ));
    }
    // A server configuration names the administrators, the server key and
    // the authority; a client configuration names the trusted server and CA.
    // Its owner can rewrite it whatever its mode, so it must belong to root
    // or to the user this process runs as. Both checks describe the opened
    // descriptor, which was opened without following a symlink.
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        // SAFETY: geteuid has no preconditions and cannot fail.
        let euid = unsafe { libc::geteuid() };
        let owner = metadata.uid();
        if owner != 0 && owner != euid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "configuration is owned by uid {owner}, not by root or this process's user \
                     (uid {euid}): its owner can rewrite it whatever its mode"
                ),
            ));
        }
        if metadata.permissions().mode() & 0o022 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "configuration must not be writable by group or others",
            ));
        }
    }
    let mut text = String::new();
    file.take(MAX_CONFIG_BYTES + 1).read_to_string(&mut text)?;
    if text.len() as u64 > MAX_CONFIG_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "configuration grew beyond 64 KiB",
        ));
    }
    // Do not echo untrusted config values (which might accidentally contain secrets).
    toml::from_str(&text)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid witness configuration"))
}

fn inspect_request() -> Request {
    Request {
        authorization: None,
        operation_id: *Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    }
}

/// Print what a command reports. A reader that has gone (`| head -1`) has
/// what it wanted, so a closed pipe is not an error; `println!` would panic
/// on it and replace the exit status with 101. Any other failure to write
/// is the command's failure.
fn print_result(text: &str) -> io::Result<()> {
    let mut out = io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(error) if error.kind() != io::ErrorKind::BrokenPipe => Err(io::Error::new(
            error.kind(),
            format!("writing the output failed: {error}"),
        )),
        _ => Ok(()),
    }
}

fn report_initialization(record: &Record) -> io::Result<()> {
    let json = serde_json::to_string(record)?;
    let mut stdout = io::stdout().lock();
    if let Err(error) = writeln!(stdout, "{json}").and_then(|()| stdout.flush()) {
        if error.kind() != io::ErrorKind::BrokenPipe {
            let _ = writeln!(
                io::stderr().lock(),
                "maki-witness: warning: witness was initialized, but writing the record failed: {error}"
            );
        }
    }
    Ok(())
}

/// Why a command did not complete.
enum Failure {
    /// The command line was refused before anything was done (status 2,
    /// as in the other binaries).
    Usage(String),
    /// The command failed (status 1).
    Failed(io::Error),
}

impl From<io::Error> for Failure {
    fn from(error: io::Error) -> Self {
        Self::Failed(error)
    }
}

fn volume_identity(text: &str) -> Result<Uuid, Failure> {
    let identity = Uuid::parse_str(text)
        .map_err(|_| Failure::Usage("volume identity must be a UUID".into()))?;
    // `init`'s state store refuses the nil identity too, before it opens or
    // creates anything, but `init-etcd` reads its configuration first, and
    // either failure exits 1: a bad argument is misuse, refused with status
    // 2 before anything is read or created.
    if identity.is_nil() {
        return Err(Failure::Usage("volume identity must be nonzero".into()));
    }
    Ok(identity)
}

fn run(args: &[String]) -> Result<(), Failure> {
    // A word that starts with `-` where a command expects its path is an
    // option in the wrong place (`serve --help`): refused before a file is
    // opened or a state directory created. A path that starts with `-` is
    // named `./-name`.
    if let [command, path, ..] = args {
        let takes_path = matches!(
            command.as_str(),
            "init" | "init-etcd" | "serve" | "inspect" | "fingerprint"
        );
        if takes_path && path.starts_with('-') {
            return Err(Failure::Usage(format!(
                "{command}: expected a path, found the option {path:?}\n{HELP}"
            )));
        }
    }
    match args {
        [help] if help == "--help" || help == "-h" => print_result(HELP)?,
        // BUG-112: every deployed binary reports its revision.
        [version] if version == "--version" || version == "-V" => {
            print_result(concat!("maki-witness ", env!("CARGO_PKG_VERSION"), "\n"))?;
        }
        [command, directory, identity] if command == "init" => {
            let identity = volume_identity(identity)?;
            let mut store = StateStore::create(Path::new(directory), *identity.as_bytes())?;
            let record = store.handle(Role::Admin, &inspect_request())?;
            report_initialization(&record)?;
        }
        [command, path] if command == "serve" => {
            let config: ServiceConfig = read_config(Path::new(path))?;
            if config.state_dir.is_some() == config.etcd.is_some() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "serve requires exactly one local or etcd authority",
                )
                .into());
            }
            // Each pending handshake and worker holds descriptors; systemd's
            // default soft limit of 1024 is reachable at max_connections =
            // 256 (BUG-124 raised it for the other binaries).
            if let Err(error) = maki_backing::raise_open_file_limit() {
                diagnostic!(
                    "maki-witness: warning: cannot raise the open-file soft limit: {error}"
                );
            }
            // Validate credentials before opening state; never create state during serve.
            let server = Arc::new(Server::new(config.server)?);
            let handler = if let Some(etcd) = config.etcd {
                maki_witness::etcd::state_handler(EtcdStore::open(etcd)?)
            } else {
                state_handler(StateStore::open(
                    config.state_dir.as_ref().expect("validated authority"),
                )?)
            };
            let listener = TcpListener::bind(config.listen)?;
            // Nobody reading the address is no reason not to serve.
            print_result(&format!(
                "maki-witness listening {}\n",
                listener.local_addr()?
            ))?;
            server.serve(listener, handler)?;
        }
        [command, path, identity] if command == "init-etcd" => {
            let identity = volume_identity(identity)?;
            let store = EtcdStore::create(
                read_config::<EtcdOptions>(Path::new(path))?,
                *identity.as_bytes(),
            )?;
            let record = store.handle(Role::Admin, &inspect_request())?;
            report_initialization(&record)?;
        }
        [command, path] if command == "inspect" => {
            let client = Client::new(read_config::<ClientOptions>(Path::new(path))?)?;
            let record = Rpc::call(&client, &inspect_request())?;
            let json = serde_json::to_string(&record).map_err(io::Error::from)?;
            print_result(&format!("{json}\n"))?;
        }
        [command, path] if command == "fingerprint" => {
            print_result(&format!(
                "{}\n",
                certificate_file_fingerprint(Path::new(path))?
            ))?;
        }
        _ => return Err(Failure::Usage(HELP.into())),
    }
    Ok(())
}

fn main() -> ExitCode {
    // `std::env::args` panics on an argument that is not UTF-8 (status
    // 101). Such an argument is misuse, as in `maki`: the state directory
    // and the certificates are also named in configuration files, which are
    // UTF-8.
    let Ok(args) = std::env::args_os()
        .skip(1)
        .map(OsString::into_string)
        .collect::<Result<Vec<_>, _>>()
    else {
        diagnostic!("maki-witness: command-line arguments must be valid UTF-8");
        return ExitCode::from(2);
    };
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(Failure::Usage(message)) => {
            diagnostic!("maki-witness: {message}");
            ExitCode::from(2)
        }
        Err(Failure::Failed(error)) => {
            diagnostic!("maki-witness: {error}");
            ExitCode::FAILURE
        }
    }
}
