//! gRPC method paths (SPEC §18): `[crypto.grpc] encrypt_path` and
//! `decrypt_path`.
//!
//! Configuration validation and the gRPC provider check a method path with
//! the same [`check_grpc_method_path`], so a path that validates is one the
//! provider builds and sends exactly as written, and `volume create` never
//! accepts a path that fails every attach.

/// The longest method path the gRPC client's URI type
/// (`http::uri::PathAndQuery`, at most `u16::MAX - 1` bytes) can hold.
pub const MAX_GRPC_METHOD_PATH_BYTES: usize = 65_534;

/// Check a gRPC method path as it is sent. HTTP/2 carries it as the `:path`
/// pseudo-header, which RFC 9113 §8.3.1 defines as an RFC 3986
/// `absolute-path`, optionally followed by `?` and a query: the path must
/// start with `/` and may contain only letters, digits, the characters
/// `-._~!$&'()*+,;=:@/`, `%XX` escapes and `?`. A `#` fragment is refused
/// because it is never sent, and `*` or a bare `?query` because they name no
/// method. Every path this accepts is one the client's URI type parses
/// unchanged.
///
/// The error says what is wrong without quoting the path, which may carry a
/// token.
pub fn check_grpc_method_path(path: &str) -> Result<(), &'static str> {
    if !path.starts_with('/') {
        return Err("must start with '/'");
    }
    if path.len() > MAX_GRPC_METHOD_PATH_BYTES {
        return Err("must be at most 65534 bytes long");
    }
    let bytes = path.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let escape = bytes.get(i + 1..i + 3);
                if !escape.is_some_and(|hex| hex.iter().all(u8::is_ascii_hexdigit)) {
                    return Err("has a '%' that does not start a %XX escape");
                }
                i += 3;
                continue;
            }
            b'#' => {
                return Err("must not contain '#': a URI fragment is never sent");
            }
            byte if is_path_or_query_byte(byte) => {}
            _ => {
                return Err(
                    "may contain only letters, digits, -._~!$&'()*+,;=:@/?, and %XX escapes \
                     (RFC 3986 path and query characters)",
                );
            }
        }
        i += 1;
    }
    Ok(())
}

/// RFC 3986 `pchar` without `pct-encoded`, plus `/` and `?`: every byte of
/// `absolute-path [ "?" query ]` other than an escape.
fn is_path_or_query_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'-' | b'.'
                | b'_'
                | b'~'
                | b'!'
                | b'$'
                | b'&'
                | b'\''
                | b'('
                | b')'
                | b'*'
                | b'+'
                | b','
                | b';'
                | b'='
                | b':'
                | b'@'
                | b'/'
                | b'?'
        )
}
