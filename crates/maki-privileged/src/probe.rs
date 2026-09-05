//! Pure parsers for what the Linux executor observes (review M-006 /
//! M-016). Keeping them free of I/O makes the mount-identity and device
//! allocation logic testable on every platform; `exec` only feeds them
//! file contents.

/// What `/proc/self/mountinfo` says about one mountpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    pub source: String,
    pub fstype: String,
    /// The mounted block device's `major:minor` (field 3), the handle
    /// for walking its sysfs topology.
    pub major_minor: String,
}

/// Follow the `slaves` relation (device-mapper, MD) from `start` down to
/// the block devices that have none: the physical devices a filesystem's
/// bytes end up on. `slaves_of` answers with the sysfs names of a device's
/// slaves (`/sys/class/block/<name>/slaves`). Bounded depth and a seen set
/// keep a cyclic or absurd tree from looping. Sorted, deduplicated.
pub fn resolve_leaf_devices(
    start: &str,
    slaves_of: &mut dyn FnMut(&str) -> Vec<String>,
) -> Vec<String> {
    const MAX_DEPTH: usize = 16;
    let mut leaves = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut stack = vec![(start.to_string(), 0usize)];
    while let Some((device, depth)) = stack.pop() {
        if !seen.insert(device.clone()) || depth > MAX_DEPTH {
            continue;
        }
        let slaves = slaves_of(&device);
        if slaves.is_empty() {
            leaves.push(device);
        } else {
            for slave in slaves {
                stack.push((slave, depth + 1));
            }
        }
    }
    leaves.sort();
    leaves.dedup();
    leaves
}

/// The `/dev/nbdN` a sysfs block name belongs to: `nbd3` itself or one of
/// its partitions (`nbd3p1`). Anything else is not an NBD device.
pub fn nbd_device_of(name: &str) -> Option<String> {
    let rest = name.strip_prefix("nbd")?;
    let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return None;
    }
    let after = &rest[digits.len()..];
    let partition = after
        .strip_prefix('p')
        .map(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false);
    if after.is_empty() || partition {
        Some(format!("/dev/nbd{digits}"))
    } else {
        None
    }
}

/// Decode the octal escapes mountinfo uses (`\040` for a space, ...).
fn unescape(field: &str) -> String {
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
            major_minor: left[2].to_string(),
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
