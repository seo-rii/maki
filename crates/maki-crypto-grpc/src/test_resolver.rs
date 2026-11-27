//! The TCP connector's resolver in this crate's tests: the system's, as in
//! production, unless a test names the addresses that every name resolves
//! to (`connect_tests.rs`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use hyper_util::client::legacy::connect::dns::{GaiResolver, Name};
use tonic::codegen::Service;

#[derive(Clone)]
pub(crate) struct TestResolver(Option<Arc<[SocketAddr]>>);

impl TestResolver {
    /// The system's resolver.
    pub(crate) fn new() -> Self {
        Self(None)
    }

    /// Every name resolves to `addresses`, in their order.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub(crate) fn fixed(addresses: &[SocketAddr]) -> Self {
        Self(Some(addresses.into()))
    }
}

type Resolving =
    Pin<Box<dyn Future<Output = std::io::Result<std::vec::IntoIter<SocketAddr>>> + Send>>;

impl Service<Name> for TestResolver {
    type Response = std::vec::IntoIter<SocketAddr>;
    type Error = std::io::Error;
    type Future = Resolving;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, name: Name) -> Self::Future {
        match &self.0 {
            Some(addresses) => {
                let addresses = addresses.to_vec();
                Box::pin(async move { Ok(addresses.into_iter()) })
            }
            None => {
                let resolving = GaiResolver::new().call(name);
                Box::pin(async move { Ok(resolving.await?.collect::<Vec<_>>().into_iter()) })
            }
        }
    }
}
