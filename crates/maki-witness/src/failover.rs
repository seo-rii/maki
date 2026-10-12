//! Identity-pinned endpoint failover for one shared freshness authority.
use std::collections::HashSet;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use crate::{Client, ClientOptions};
use maki_backing::remote_witness::{Record, Request, Rpc};

/// Each call tries every configured frontend at most once, sharing one deadline.
/// The operation, including its idempotency key and predecessor, stays identical.
pub struct FailoverClient {
    endpoints: Vec<Client>,
    identity: [u8; 16],
    timeout: std::time::Duration,
    // A routing hint only: no authoritative records or outcomes are cached.
    preferred: AtomicUsize,
}
impl FailoverClient {
    pub fn new(
        endpoints: Vec<ClientOptions>,
        identity: [u8; 16],
        timeout_ms: u64,
    ) -> io::Result<Self> {
        let timeout = crate::timeout(timeout_ms)?;
        let mut addresses = HashSet::new();
        if endpoints.is_empty()
            || endpoints.len() > 8
            || identity == [0; 16]
            || endpoints
                .iter()
                .any(|endpoint| endpoint.address.port() == 0 || !addresses.insert(endpoint.address))
        {
            return Err(crate::invalid(
                "failover requires 1..=8 unique endpoints and a nonzero authority identity",
            ));
        }
        let endpoints = endpoints
            .into_iter()
            .map(Client::new)
            .collect::<io::Result<_>>()?;
        Ok(Self {
            endpoints,
            identity,
            timeout,
            preferred: AtomicUsize::new(0),
        })
    }
}
impl Rpc for FailoverClient {
    fn call(&self, request: &Request) -> io::Result<Record> {
        if request
            .expected
            .as_ref()
            .is_some_and(|expected| expected.identity != self.identity)
        {
            return Err(crate::corrupt(
                "request differs from pinned witness identity",
            ));
        }
        let deadline = Instant::now() + self.timeout;
        let mut last = io::Error::new(io::ErrorKind::TimedOut, "witness endpoints unavailable");
        let preferred = self.preferred.load(Ordering::Acquire);
        for attempt in 0..self.endpoints.len() {
            let index = (preferred + attempt) % self.endpoints.len();
            let endpoint = &self.endpoints[index];
            let remaining = crate::remaining(deadline)?;
            // Reserve time for every untried endpoint, including a stalled TLS handshake.
            let slice = remaining / (self.endpoints.len() - attempt) as u32;
            let attempt_deadline = Instant::now() + slice;
            match endpoint.call_until::<_, Record>(request, attempt_deadline.min(deadline)) {
                Ok(record) => {
                    record.validate()?;
                    if record.identity != self.identity {
                        return Err(crate::corrupt(
                            "response differs from pinned witness identity",
                        ));
                    }
                    self.preferred.store(index, Ordering::Release);
                    return Ok(record);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::InvalidInput
                            | io::ErrorKind::InvalidData
                            | io::ErrorKind::PermissionDenied
                            | io::ErrorKind::WouldBlock
                    ) =>
                {
                    return Err(error)
                }
                Err(error) => last = error,
            }
        }
        Err(last)
    }
}
