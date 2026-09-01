//! Control protocol: one JSON object per line, bounded line length.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Hard bound on a single protocol line (requests and responses).
pub const MAX_LINE: usize = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    pub command: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    #[serde(default, skip_serializing_if = "Value::is_null")]
    pub payload: Value,
}

impl Request {
    pub fn new(command: &str) -> Self {
        Self {
            command: command.to_string(),
            section: None,
            payload: Value::Null,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("protocol line exceeds {MAX_LINE} bytes")]
    LineTooLong,
    #[error("connection closed")]
    Closed,
    #[error("invalid JSON: {0}")]
    Json(#[from] serde_json::Error),
}

/// Read one bounded line. Returns `Closed` on clean EOF before any byte.
pub async fn read_line<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Vec<u8>, ProtocolError> {
    let mut line = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match rd.read(&mut byte).await? {
            0 => {
                return if line.is_empty() {
                    Err(ProtocolError::Closed)
                } else {
                    Ok(line)
                }
            }
            _ => {
                if byte[0] == b'\n' {
                    return Ok(line);
                }
                line.push(byte[0]);
                if line.len() > MAX_LINE {
                    return Err(ProtocolError::LineTooLong);
                }
            }
        }
    }
}

pub async fn send_command<W: AsyncWrite + Unpin>(
    wr: &mut W,
    request: &Request,
) -> Result<(), ProtocolError> {
    let mut bytes = serde_json::to_vec(request)?;
    bytes.push(b'\n');
    wr.write_all(&bytes).await?;
    wr.flush().await?;
    Ok(())
}

pub async fn read_response<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Value, ProtocolError> {
    let line = read_line(rd).await?;
    Ok(serde_json::from_slice(&line)?)
}
