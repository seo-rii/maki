//! Single-authority witness process. Initialization is always explicit.
use std::io::{self, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use maki_backing::remote_witness::{Action, Request, Role, Rpc, StateStore};
use maki_witness::{
    certificate_file_fingerprint, state_handler, Client, ClientOptions, Server, ServerOptions,
};
use serde::de::DeserializeOwned;
use serde::Deserialize;
use uuid::Uuid;

const HELP: &str = "maki-witness init STATE_DIRECTORY VOLUME_UUID\nmaki-witness serve SERVER_CONFIG.toml\nmaki-witness inspect CLIENT_CONFIG.toml\nmaki-witness fingerprint CERTIFICATE.pem\n\ninit refuses existing state; serve never initializes missing state.\nTLS 1.3 and certificate allow-list authentication are mandatory.\n";
const MAX_CONFIG_BYTES: u64 = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceConfig {
    state_dir: PathBuf,
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
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
        operation_id: *Uuid::new_v4().as_bytes(),
        expected: None,
        action: Action::Inspect,
    }
}

fn run(args: &[String]) -> io::Result<()> {
    match args {
        [help] if help == "--help" || help == "-h" => print!("{HELP}"),
        [command, directory, identity] if command == "init" => {
            let identity = Uuid::parse_str(identity).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "volume identity must be a UUID",
                )
            })?;
            let mut store = StateStore::create(Path::new(directory), *identity.as_bytes())?;
            let record = store.handle(Role::Admin, &inspect_request())?;
            serde_json::to_writer(io::stdout().lock(), &record)?;
            println!();
        }
        [command, path] if command == "serve" => {
            let config: ServiceConfig = read_config(Path::new(path))?;
            // Validate credentials before opening state; never create state during serve.
            let server = Arc::new(Server::new(config.server)?);
            let store = StateStore::open(&config.state_dir)?;
            let listener = TcpListener::bind(config.listen)?;
            println!("maki-witness listening {}", listener.local_addr()?);
            io::stdout().flush()?;
            server.serve(listener, state_handler(store))?;
        }
        [command, path] if command == "inspect" => {
            let client = Client::new(read_config::<ClientOptions>(Path::new(path))?)?;
            let record = Rpc::call(&client, &inspect_request())?;
            serde_json::to_writer(io::stdout().lock(), &record)?;
            println!();
        }
        [command, path] if command == "fingerprint" => {
            println!("{}", certificate_file_fingerprint(Path::new(path))?);
        }
        _ => return Err(io::Error::new(io::ErrorKind::InvalidInput, HELP)),
    }
    Ok(())
}

fn main() {
    if let Err(error) = run(&std::env::args().skip(1).collect::<Vec<_>>()) {
        eprintln!("maki-witness: {error}");
        std::process::exit(1);
    }
}
