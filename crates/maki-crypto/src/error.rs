//! Crypto error taxonomy (SPEC §31).

/// Classification driving retry/circuit-breaker behavior (SPEC §31).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorClass {
    /// Transient; retry with backoff against the same endpoint.
    Retryable,
    /// Explicit throttle signal (e.g. HTTP 429); currently retried exactly like
    /// `Retryable`, with no extra backoff.
    Throttled,
    /// The request itself is invalid or the data is bad; retrying is useless.
    NonRetryableRequest,
    /// This endpoint is unusable (e.g. TLS identity failure); fail over.
    EndpointFatal,
    /// The whole provider is misconfigured or incompatible; stop.
    ProviderFatal,
}

/// Context fields a provider may explicitly refuse to interpret. This is
/// distinct from authentication failure and is evidence only when a self-test
/// intentionally changes the same field.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ContextField {
    #[error("format version")]
    FormatVersion,
    #[error("compatibility id")]
    CompatibilityId,
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
    #[error("unsupported crypto context: {0}")]
    UnsupportedContext(ContextField),
    /// Ciphertext failed authentication/integrity verification.
    /// Corrupted encrypted data is never returned as plaintext (SPEC §12).
    #[error("integrity failure: {0}")]
    Integrity(String),
    /// The provider violated its declared contract (size, order, count…).
    #[error("provider contract violation: {0}")]
    Contract(String),
    /// A transport failure that provably happened before any byte of the
    /// request left Maki; see [`CryptoError::not_sent`]. Class and message
    /// are the inner error's.
    #[error(transparent)]
    NotSent(NotSentError),
}

/// The error inside [`CryptoError::NotSent`]. Only
/// [`CryptoError::not_sent`] builds one, so it always holds an unmarked
/// `Retryable`, `Throttled` or `EndpointFatal` error.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct NotSentError(Box<CryptoError>);

impl NotSentError {
    /// The transport error itself.
    pub fn error(&self) -> &CryptoError {
        &self.0
    }
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
            CryptoError::ProviderFatal(_)
            | CryptoError::UnsupportedContext(_)
            | CryptoError::Contract(_) => ErrorClass::ProviderFatal,
            CryptoError::NotSent(inner) => inner.0.class(),
        }
    }

    /// Mark an error that a transport raised before writing any byte of the
    /// request: it failed to connect, to complete TLS or a WebSocket
    /// upgrade, or to hand the request to its connection. Such a request
    /// cannot have reached the provider, so the dispatcher may send it to
    /// another endpoint even when the provider is not retry-safe (SPEC
    /// §18). Mark only what the transport can prove; anything after the
    /// first request byte may have been written must stay unmarked.
    ///
    /// Only the classes the dispatcher fails over on (`Retryable`,
    /// `Throttled`, `EndpointFatal`) are marked. Other errors end the
    /// operation whether or not the request was sent, so they are returned
    /// unchanged; marking is idempotent.
    pub fn not_sent(self) -> Self {
        match self.class() {
            ErrorClass::Retryable | ErrorClass::Throttled | ErrorClass::EndpointFatal
                if !self.is_not_sent() =>
            {
                CryptoError::NotSent(NotSentError(Box::new(self)))
            }
            _ => self,
        }
    }

    /// Whether the transport proved that no byte of the request was sent.
    pub fn is_not_sent(&self) -> bool {
        matches!(self, CryptoError::NotSent(_))
    }

    /// Drop the not-sent mark, keeping class and message: an earlier
    /// attempt of the same call may have reached a provider.
    pub fn maybe_sent(self) -> Self {
        match self {
            CryptoError::NotSent(inner) => *inner.0,
            other => other,
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
            CryptoError::UnsupportedContext(field) => CryptoError::UnsupportedContext(*field),
            CryptoError::Integrity(m) => CryptoError::Integrity(m.clone()),
            CryptoError::Contract(m) => CryptoError::Contract(m.clone()),
            CryptoError::NotSent(inner) => {
                CryptoError::NotSent(NotSentError(Box::new(inner.0.duplicate())))
            }
        }
    }
}
