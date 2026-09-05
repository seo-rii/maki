//! Pure parsers for what the Linux executor observes (review M-006 /
//! M-016). Keeping them free of I/O makes the mount-identity and device
//! allocation logic testable on every platform; `exec` only feeds them
//! file contents.

/// What `/proc/self/mountinfo` says about one mountpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub source: String,
    pub fstype: String,
}

/// Decode the octal escapes mountinfo uses (`\040` for a space, ...).
pub(crate) fn unescape(field: &str) -> String {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 4 <= bytes.len() {
            if let Some(oct) = field.get(i + 1..i + 4) {
                if let Ok(v) = u8::from_str_radix(oct, 8) {
                    out.push(v);
                    i += 4;
                    continue;
                }
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Find the entry mounted exactly at `mountpoint`. When a path is mounted
/// more than once the *last* line wins (it is the visible mount).
pub fn parse_mountinfo(text: &str, mountpoint: &str) -> Option<MountEntry> {
    let mut found = None;
    for line in text.lines() {
        // id parent major:minor root mountpoint options [optional...] - fstype source superopts
        let (left, right) = match line.split_once(" - ") {
            Some(parts) => parts,
            None => continue,
        };
        let left: Vec<&str> = left.split_whitespace().collect();
        if left.len() < 5 {
            continue;
        }
        if unescape(left[4]) != mountpoint {
            continue;
        }
        let right: Vec<&str> = right.split_whitespace().collect();
        if right.len() < 2 {
            continue;
        }
        found = Some(MountEntry {
            fstype: right[0].to_string(),
            source: unescape(right[1]),
        });
    }
    found
}

/// Index of a `/dev/nbdN` device.
pub fn nbd_index(device: &str) -> Option<u32> {
    device
        .strip_prefix("/dev/nbd")
        .and_then(|rest| rest.parse::<u32>().ok())
}

/// Choose the lowest-numbered device that is not connected.
/// `devices` holds `(sysfs name like "nbd3", connected)`.
pub fn choose_free_nbd(devices: &[(String, bool)]) -> Option<String> {
    let mut free: Vec<u32> = devices
        .iter()
        .filter(|(_, connected)| !connected)
        .filter_map(|(name, _)| name.strip_prefix("nbd").and_then(|n| n.parse().ok()))
        .collect();
    free.sort_unstable();
    free.first().map(|n| format!("/dev/nbd{n}"))
}
