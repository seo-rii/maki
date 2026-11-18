//! Control protocol: one JSON object per line, bounded line length.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};

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
    /// The client sent nothing for the session idle timeout (F10).
    #[error("session idle timeout")]
    IdleTimeout,
    /// The client did not drain a response within the write timeout (F10).
    #[error("response write timeout")]
    WriteTimeout,
}

/// Read a frame from a session's persistent buffered reader. Bytes prefetched
/// after the newline stay in that reader for the next frame.
pub async fn read_buffered_line<R: AsyncBufRead + Unpin>(
    rd: &mut R,
) -> Result<Vec<u8>, ProtocolError> {
    let mut line = Vec::with_capacity(256);
    // One extra byte distinguishes an exact-limit newline from an oversized
    // payload, even if the sender never terminates the frame.
    let len = rd
        .take(MAX_LINE as u64 + 1)
        .read_until(b'\n', &mut line)
        .await?;
    if len == 0 {
        return Err(ProtocolError::Closed);
    }
    if line.last() == Some(&b'\n') {
        line.pop();
    } else if len > MAX_LINE {
        return Err(ProtocolError::LineTooLong);
    }
    Ok(line)
}

/// Read one frame from an arbitrary stream without consuming the next
/// frame's bytes. Persistent sessions should use [`read_buffered_line`].
pub async fn read_line<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Vec<u8>, ProtocolError> {
    read_buffered_line(&mut BufReader::with_capacity(1, rd)).await
}

pub async fn send_command<W: AsyncWrite + Unpin>(
    wr: &mut W,
    request: &Request,
) -> Result<(), ProtocolError> {
    // Reject an oversized request before publishing any of its frame. The
    // connection can then still carry the caller's next valid command.
    let mut bytes = serialize_line(request)?;
    bytes.push(b'\n');
    wr.write_all(&bytes).await?;
    wr.flush().await?;
    Ok(())
}

/// Serialize requests and responses with the same bound as `read_line`.
/// Checking while encoding also bounds the temporary buffer when JSON escapes
/// expand a string. The framing newline is not part of the payload limit.
pub(crate) fn serialize_line(value: &impl Serialize) -> Result<Vec<u8>, ProtocolError> {
    struct LineBuffer(Vec<u8>);

    impl std::io::Write for LineBuffer {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            if bytes.len() > MAX_LINE - self.0.len() {
                return Err(std::io::Error::other("control message exceeds line limit"));
            }
            self.0.extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut buffer = LineBuffer(Vec::with_capacity(256));
    match serde_json::to_writer(&mut buffer, value) {
        Ok(()) => Ok(buffer.0),
        Err(error) if error.is_io() => Err(ProtocolError::LineTooLong),
        Err(error) => Err(error.into()),
    }
}

pub async fn read_response<R: AsyncRead + Unpin>(rd: &mut R) -> Result<Value, ProtocolError> {
    let line = read_line(rd).await?;
    Ok(serde_json::from_slice(&line)?)
}

/// Read a response efficiently, keeping subsequent frames in the same reader.
pub async fn read_buffered_response<R: AsyncBufRead + Unpin>(
    rd: &mut R,
) -> Result<Value, ProtocolError> {
    let line = read_buffered_line(rd).await?;
    Ok(serde_json::from_slice(&line)?)
}
