//! The TLS roots every remote crypto transport trusts (SPEC §18).
//!
//! HTTP, WebSocket and gRPC verify a server's certificate chain against one
//! set of roots, the union of:
//!
//! - the host's trust store: the system CA bundle, or the files that
//!   `SSL_CERT_FILE` and `SSL_CERT_DIR` name when either is set. It is read
//!   best effort: a missing or unreadable store adds nothing, and a
//!   certificate in it that does not parse is skipped, because system
//!   bundles carry old or malformed entries. A private CA installed there is
//!   trusted by every transport.
//! - the public roots compiled into the binary ([`COMPILED_IN_ROOTS`], the
//!   webpki-roots set), so an image without a system bundle still reaches a
//!   public endpoint. They also make the set never empty: a transport is
//!   always built, and an endpoint none of the roots vouches for is refused
//!   at the handshake.
//! - the configured CA bundle (`ca_file`), which adds to the other two and is
//!   parsed strictly: every member must be a valid certificate and a bundle
//!   without one is refused, so a valid root cannot hide a damaged one.
//!
//! The store is read when [`trusted_roots`] is called; each transport says
//! when it calls it. The remote witness client is not a crypto transport and
//! does not use this: it trusts only its configured CA (maki-witness).

use rustls::pki_types::{pem::PemObject as _, CertificateDer, TrustAnchor};
use rustls::RootCertStore;

/// The public roots compiled into the binary (webpki-roots).
pub const COMPILED_IN_ROOTS: &[TrustAnchor<'static>] = webpki_roots::TLS_SERVER_ROOTS;

/// Why a configured CA bundle is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CaBundleError {
    #[error("custom TLS CA bundle is not valid PEM")]
    Encoding,
    #[error("custom TLS CA bundle contains no certificates")]
    NoCertificates,
    #[error("custom TLS CA bundle holds an invalid certificate")]
    InvalidCertificate,
}

/// The roots a remote transport trusts: the certificates of `ca_pem` (the
/// configured `ca_file`), the host's trust store and [`COMPILED_IN_ROOTS`].
pub fn trusted_roots(ca_pem: Option<&[u8]>) -> Result<RootCertStore, CaBundleError> {
    let mut roots = RootCertStore::empty();
    if let Some(pem) = ca_pem {
        add_ca_bundle(&mut roots, pem)?;
    }
    roots.add_parsable_certificates(rustls_native_certs::load_native_certs().certs);
    roots.extend(COMPILED_IN_ROOTS.iter().cloned());
    Ok(roots)
}

fn add_ca_bundle(roots: &mut RootCertStore, pem: &[u8]) -> Result<(), CaBundleError> {
    let certificates = CertificateDer::pem_slice_iter(pem)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| CaBundleError::Encoding)?;
    if certificates.is_empty() {
        return Err(CaBundleError::NoCertificates);
    }
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|_| CaBundleError::InvalidCertificate)?;
    }
    Ok(())
}
