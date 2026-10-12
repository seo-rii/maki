//! Real TCP request capture shared by URL and method configuration regressions.

use std::io::{Read, Write};
use std::net::TcpListener;
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use maki_crypto::{
    CiphertextUnit, CryptoContext, CryptoError, CryptoProvider, PlaintextUnit, SecretBuffer,
};
use maki_crypto_http::HttpCryptoProvider;
use maki_crypto_local::keysource::MapKeySource;

pub struct Case<'a> {
    pub base_suffix: &'a str,
    pub operation_path: &'a str,
    pub method: &'a str,
    pub canonical_method: &'a str,
    pub expected_target: &'a str,
    pub configured_query: bool,
    pub decrypt: bool,
}

pub struct Observation {
    pub request_line: String,
    pub result: Result<usize, CryptoError>,
}

pub fn exchange(case: Case<'_>) -> Observation {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let expected_target = case.expected_target.to_string();
    let expected_method = case.canonical_method.to_string();
    let (sender, receiver) = mpsc::channel();
    let server = thread::spawn(move || {
        let (mut connection, _) = listener.accept().unwrap();
        connection
            .set_read_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let mut data = Vec::new();
        let mut buffer = [0; 2048];
        let header_end = loop {
            let count = connection.read(&mut buffer).unwrap();
            assert!(count > 0);
            data.extend_from_slice(&buffer[..count]);
            if let Some(position) = data.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                break position + 4;
            }
        };
        let header = std::str::from_utf8(&data[..header_end]).unwrap();
        let request_line = header.lines().next().unwrap().to_string();
        let length = header
            .lines()
            .find_map(|line| {
                line.to_ascii_lowercase()
                    .strip_prefix("content-length: ")
                    .and_then(|value| value.trim().parse::<usize>().ok())
            })
            .unwrap_or(0);
        while data.len() < header_end + length {
            let count = connection.read(&mut buffer).unwrap();
            assert!(count > 0);
            data.extend_from_slice(&buffer[..count]);
        }
        let parts: Vec<_> = request_line.split_whitespace().collect();
        let status = if parts[0] != expected_method {
            "405 Method Not Allowed"
        } else if parts[1] != expected_target {
            "404 Not Found"
        } else {
            "200 OK"
        };
        sender.send(request_line).unwrap();
        let response = [0x22; 512];
        write!(
            connection,
            "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response.len()
        )
        .unwrap();
        // An error status lets the client close before consuming the body.
        let _ = connection.write_all(&response);
    });
    let endpoint = format!("http://{address}{}", case.base_suffix);
    let (encrypt_method, encrypt_path, decrypt_method, decrypt_path) = if case.decrypt {
        ("POST", "/encrypt", case.method, case.operation_path)
    } else {
        (case.method, case.operation_path, "POST", "/decrypt")
    };
    let query = if case.configured_query {
        "trace = \"requested value\"\n"
    } else {
        ""
    };
    let encrypt_query = if !case.decrypt && case.configured_query {
        format!("[crypto.http.encrypt.query]\n{query}")
    } else {
        String::new()
    };
    let decrypt_query = if case.decrypt && case.configured_query {
        format!("[crypto.http.decrypt.query]\n{query}")
    } else {
        String::new()
    };
    let text = format!(
        r#"
config_schema_version = 1
[volume]
name = "audit-http-mapping"
max_virtual_size = "1MiB"
device_block_size = 512
crypto_unit_size = 512
shard_logical_size = "64KiB"
[crypto]
provider = "remote-http"
crypto_compatibility_id = "audit-http-mapping-v1"
[crypto.capabilities]
supported_plaintext_sizes = [512]
max_ciphertext_size = 512
[[crypto.http.endpoint]]
name = "a"
url = "{endpoint}"
[crypto.http.encrypt]
method = "{encrypt_method}"
path = "{encrypt_path}"
{encrypt_query}
[crypto.http.decrypt]
method = "{decrypt_method}"
path = "{decrypt_path}"
{decrypt_query}
[backing]
root = "/tmp/unused"
"#
    );
    let config = maki_format::config::parse_config(&text).unwrap();
    config.validate().unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let result = runtime.block_on(async {
        let provider =
            HttpCryptoProvider::from_config(&config, &endpoint, &MapKeySource::new()).unwrap();
        let context = CryptoContext {
            volume_uuid: Default::default(),
            format_version: 1,
            crypto_compatibility_id: "audit-http-mapping-v1".into(),
        };
        if case.decrypt {
            provider
                .decrypt_batch(
                    &context,
                    &[CiphertextUnit {
                        unit_index: 0,
                        data: vec![0x11; 512],
                    }],
                )
                .await
                .map(|items| items.len())
        } else {
            provider
                .encrypt_batch(
                    &context,
                    &[PlaintextUnit {
                        unit_index: 0,
                        data: SecretBuffer::from_slice(&[0x11; 512]),
                    }],
                )
                .await
                .map(|items| items.len())
        }
    });
    let request_line = receiver.recv_timeout(Duration::from_secs(5)).unwrap();
    server.join().unwrap();
    Observation {
        request_line,
        result,
    }
}
