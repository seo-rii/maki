//! TLS material is read at attach, as root, from configured paths. A
//! combined certificate/private-key PEM (`client_cert_file` without
//! `client_key`, HTTP only) holds the mTLS private key, so it must pass the
//! same checks as a `file` credential: opened once without following a
//! symlink, a regular file, and not readable by group or others. Any TLS
//! file must be a regular file, so a FIFO cannot hang attach. Certificates
//! and CA bundles may still be symlinks (`/etc/ssl/certs`, certbot).
#![cfg(unix)]

use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use maki_crypto_http::read_tls_file;

fn write(path: &Path, bytes: &[u8], mode: u32) {
    std::fs::write(path, bytes).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn identity_pem() -> Vec<u8> {
    let identity = rcgen::generate_simple_self_signed(vec!["maki-client".into()]).unwrap();
    format!("{}{}", identity.key_pair.serialize_pem(), identity.cert.pem()).into_bytes()
}

#[test]
fn a_combined_identity_pem_readable_by_others_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("id.pem");
    write(&path, &identity_pem(), 0o644);
    let error = read_tls_file("http", "client_cert_file", path.to_str().unwrap(), true).unwrap_err();
    assert!(error.to_string().contains("private key"), "{error}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        read_tls_file("http", "client_cert_file", path.to_str().unwrap(), true).unwrap(),
        identity_pem_len_check(&path)
    );
}

fn identity_pem_len_check(path: &Path) -> Vec<u8> {
    std::fs::read(path).unwrap()
}

#[test]
fn a_symlinked_combined_identity_pem_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("real.pem");
    write(&real, &identity_pem(), 0o600);
    let link = dir.path().join("id.pem");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    assert!(read_tls_file("http", "client_cert_file", link.to_str().unwrap(), true).is_err());
}

#[test]
fn certificates_may_be_symlinks_and_world_readable() {
    let identity = rcgen::generate_simple_self_signed(vec!["maki-client".into()]).unwrap();
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("cert.pem");
    write(&real, identity.cert.pem().as_bytes(), 0o644);
    let link = dir.path().join("link.pem");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    // A certificate paired with a separate client_key, or a CA bundle.
    read_tls_file("http", "client_cert_file", link.to_str().unwrap(), false).unwrap();
    read_tls_file("http", "ca_file", link.to_str().unwrap(), false).unwrap();
    // A certificate-only file in the combined slot is not a secret either.
    read_tls_file("http", "client_cert_file", real.to_str().unwrap(), true).unwrap();
}

#[test]
fn a_fifo_is_refused_without_blocking() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("fifo.pem");
    let c_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: a valid NUL-terminated path.
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    assert!(read_tls_file("http", "ca_file", fifo.to_str().unwrap(), false).is_err());
    assert!(read_tls_file("http", "client_cert_file", fifo.to_str().unwrap(), true).is_err());
}
