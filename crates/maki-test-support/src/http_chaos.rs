//! Minimal in-process HTTP/1.1 chaos server for remote-provider tests: records
//! every request, and a pluggable handler decides status/body/delay/drop.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[derive(Debug, Clone)]
pub struct RecordedRequest {
    pub method: String,
    pub path: String,
    pub query: BTreeMap<String, String>,
    pub headers: BTreeMap<String, String>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct ResponseSpec {
    pub status: u16,
    pub body: Vec<u8>,
    pub content_type: String,
    pub delay: Duration,
    /// Close the socket mid-response (truncated body).
    pub drop_after: Option<usize>,
    /// Extra response headers (e.g. `Location` for a redirect).
    pub headers: Vec<(String, String)>,
}

impl ResponseSpec {
    pub fn json(value: &serde_json::Value) -> Self {
        Self {
            status: 200,
            body: serde_json::to_vec(value).unwrap(),
            content_type: "application/json".to_string(),
            delay: Duration::ZERO,
            drop_after: None,
            headers: Vec::new(),
        }
    }

    pub fn raw(body: Vec<u8>) -> Self {
        Self {
            status: 200,
            body,
            content_type: "application/octet-stream".to_string(),
            delay: Duration::ZERO,
            drop_after: None,
            headers: Vec::new(),
        }
    }

    pub fn status(status: u16) -> Self {
        Self {
            status,
            body: b"{}".to_vec(),
            content_type: "application/json".to_string(),
            delay: Duration::ZERO,
            drop_after: None,
            headers: Vec::new(),
        }
    }
}

pub type Handler = Arc<dyn Fn(&RecordedRequest) -> ResponseSpec + Send + Sync>;

pub struct TestServer {
    pub addr: SocketAddr,
    pub requests: Arc<Mutex<Vec<RecordedRequest>>>,
    handler: Arc<Mutex<Handler>>,
}

impl TestServer {
    pub async fn start(handler: Handler) -> Arc<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = Arc::new(Self {
            addr,
            requests: Arc::new(Mutex::new(Vec::new())),
            handler: Arc::new(Mutex::new(handler)),
        });
        let s2 = server.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let server = s2.clone();
                tokio::spawn(async move {
                    let _ = server.serve_conn(stream).await;
                });
            }
        });
        server
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn set_handler(&self, handler: Handler) {
        *self.handler.lock() = handler;
    }

    async fn serve_conn(&self, mut stream: tokio::net::TcpStream) -> std::io::Result<()> {
        loop {
            let request = match read_request(&mut stream).await? {
                Some(r) => r,
                None => return Ok(()),
            };
            let spec = {
                let handler = self.handler.lock().clone();
                let spec = handler(&request);
                self.requests.lock().push(request);
                spec
            };
            if spec.delay > Duration::ZERO {
                tokio::time::sleep(spec.delay).await;
            }
            let mut head = format!(
                "HTTP/1.1 {} X\r\ncontent-type: {}\r\ncontent-length: {}\r\n",
                spec.status,
                spec.content_type,
                spec.body.len()
            );
            for (name, value) in &spec.headers {
                head.push_str(&format!("{name}: {value}\r\n"));
            }
            head.push_str("\r\n");
            stream.write_all(head.as_bytes()).await?;
            match spec.drop_after {
                Some(n) => {
                    stream
                        .write_all(&spec.body[..n.min(spec.body.len())])
                        .await?;
                    return Ok(()); // close mid-body
                }
                None => stream.write_all(&spec.body).await?,
            }
            stream.flush().await?;
        }
    }
}

async fn read_request(
    stream: &mut tokio::net::TcpStream,
) -> std::io::Result<Option<RecordedRequest>> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    // read until \r\n\r\n
    loop {
        match stream.read(&mut byte).await? {
            0 => return Ok(None),
            _ => buf.push(byte[0]),
        }
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 1 << 20 {
            return Ok(None);
        }
    }
    let head = String::from_utf8_lossy(&buf).into_owned();
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split(' ');
    let method = parts.next().unwrap_or("").to_string();
    let target = parts.next().unwrap_or("").to_string();
    let (path, query_str) = match target.split_once('?') {
        Some((p, q)) => (p.to_string(), q.to_string()),
        None => (target, String::new()),
    };
    let mut query = BTreeMap::new();
    for pair in query_str.split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        query.insert(k.to_string(), v.to_string());
    }
    let mut headers = BTreeMap::new();
    for line in lines {
        if let Some((k, v)) = line.split_once(':') {
            headers.insert(k.trim().to_lowercase(), v.trim().to_string());
        }
    }
    let len: usize = headers
        .get("content-length")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let mut body = vec![0u8; len];
    if len > 0 {
        stream.read_exact(&mut body).await?;
    }
    Ok(Some(RecordedRequest {
        method,
        path,
        query,
        headers,
        body,
    }))
}
