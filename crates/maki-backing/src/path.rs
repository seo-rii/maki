//! Relative-path validation: a backing namespace must be escape-proof.

use std::io;

/// Validate a backing-relative path: non-empty (unless `allow_empty`),
/// forward slashes, no absolute paths, no `.`/`..` components, no drive
/// letters, no backslashes, no NUL.
pub fn validate(path: &str, allow_empty: bool) -> io::Result<()> {
    if path.is_empty() {
        return if allow_empty {
            Ok(())
        } else {
            Err(invalid(path, "empty path"))
        };
    }
    if path.starts_with('/') {
        return Err(invalid(path, "absolute path"));
    }
    if path.contains('\\') || path.contains('\0') || path.contains(':') {
        return Err(invalid(path, "forbidden character"));
    }
    for comp in path.split('/') {
        if comp.is_empty() {
            return Err(invalid(path, "empty component"));
        }
        if comp == "." || comp == ".." {
            return Err(invalid(path, "dot component"));
        }
    }
    Ok(())
}

fn invalid(path: &str, why: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid backing path {path:?}: {why}"),
    )
}

/// Parent directory of a relative path ("" for top-level entries).
pub fn parent(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[..i],
        None => "",
    }
}

/// Final component of a relative path.
pub fn file_name(path: &str) -> &str {
    match path.rfind('/') {
        Some(i) => &path[i + 1..],
        None => path,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_escapes() {
        for bad in ["", "/abs", "a/../b", "..", "a//b", "a\\b", "c:evil", "a/./b"] {
            assert!(validate(bad, false).is_err(), "should reject {bad:?}");
        }
    }

    #[test]
    fn accepts_normal() {
        for good in ["superblock.a", "journal/seg-000001", "data/shard-0000/x"] {
            assert!(validate(good, false).is_ok(), "should accept {good:?}");
        }
    }

    #[test]
    fn parent_and_name() {
        assert_eq!(parent("journal/seg-1"), "journal");
        assert_eq!(parent("volume.lock"), "");
        assert_eq!(file_name("journal/seg-1"), "seg-1");
    }
}
