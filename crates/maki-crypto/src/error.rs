//! Crypto error taxonomy (SPEC §31).

/// Sanitize an externally-supplied message — a remote provider's gRPC status
/// text or WebSocket `error.message` — before it enters a Maki error or the
/// logs. Control characters (newlines and tabs included) are replaced with a
/// space so a hostile or buggy provider cannot inject log lines through the
/// tracing path, and the length is capped so it cannot flood the logs
/// (MAKI-016). This does not detect secrets a provider may reflect; the mapped
/// error class and a request id remain the primary diagnostics.
pub fn sanitize_external_message(msg: &str) -> String {
    const MAX_CHARS: usize = 200;
    let mut out = String::new();
    for (count, ch) in msg.chars().enumerate() {
        if count >= MAX_CHARS {
            out.push('…');
            break;
        }
        out.push(if ch.is_control() { ' ' } else { ch });
    }
    out
}

/// Classification driving retry/circuit-breaker behavior (SPEC §31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient; retry with backoff against the same endpoint.
    Retryable,
    /// Explicit throttle signal (e.g. HTTP 429); retry with stronger backoff.
    Throttled,
    /// The request itself is invalid or the data is bad; retrying is useless.
    NonRetryableRequest,
    /// This endpoint is unusable (e.g. TLS identity failure); fail over.
    EndpointFatal,
    /// The whole provider is misconfigured or incompatible; stop.
    ProviderFatal,
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("retryable: {0}")]
    Retryable(String),
    #[error("throttled: {0}")]
    Throttled(String),
    #[error("non-retryable request: {0}")]
    NonRetryableRequest(String),
    #[error("endpoint fatal: {0}")]
    EndpointFatal(String),
    #[error("provider fatal: {0}")]
    ProviderFatal(String),
    /// Ciphertext failed authentication/integrity verification.
    /// Corrupted encrypted data is never returned as plaintext (SPEC §12).
    #[error("integrity failure: {0}")]
    Integrity(String),
    /// The provider violated its declared contract (size, order, count…).
    #[error("provider contract violation: {0}")]
    Contract(String),
}

impl CryptoError {
    pub fn class(&self) -> ErrorClass {
        match self {
            CryptoError::Retryable(_) => ErrorClass::Retryable,
            CryptoError::Throttled(_) => ErrorClass::Throttled,
            CryptoError::NonRetryableRequest(_) | CryptoError::Integrity(_) => {
                ErrorClass::NonRetryableRequest
            }
            CryptoError::EndpointFatal(_) => ErrorClass::EndpointFatal,
            CryptoError::ProviderFatal(_) | CryptoError::Contract(_) => ErrorClass::ProviderFatal,
        }
    }

    pub fn is_retryable(&self) -> bool {
        matches!(self.class(), ErrorClass::Retryable | ErrorClass::Throttled)
    }

    /// A copy with the same class and message (errors are not `Clone` so
    /// that fan-out to several waiters stays explicit).
    pub fn duplicate(&self) -> Self {
        match self {
            CryptoError::Retryable(m) => CryptoError::Retryable(m.clone()),
            CryptoError::Throttled(m) => CryptoError::Throttled(m.clone()),
            CryptoError::NonRetryableRequest(m) => CryptoError::NonRetryableRequest(m.clone()),
            CryptoError::EndpointFatal(m) => CryptoError::EndpointFatal(m.clone()),
            CryptoError::ProviderFatal(m) => CryptoError::ProviderFatal(m.clone()),
            CryptoError::Integrity(m) => CryptoError::Integrity(m.clone()),
            CryptoError::Contract(m) => CryptoError::Contract(m.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MAKI-016: an external provider message must not carry control
    /// characters (which could inject log lines) into an error, and must be
    /// length-capped.
    #[test]
    fn sanitize_strips_control_chars_and_caps_length() {
        let s = sanitize_external_message("line1\nline2\r\tX\u{7}end");
        assert!(
            !s.contains('\n') && !s.contains('\r') && !s.contains('\t') && !s.contains('\u{7}'),
            "{s:?}"
        );
        assert_eq!(s, "line1 line2  X end");
        let capped = sanitize_external_message(&"a".repeat(1000));
        assert!(capped.chars().count() <= 201, "{}", capped.chars().count());
        assert!(capped.ends_with('…'));
        assert_eq!(sanitize_external_message("ok"), "ok");
    }
}
