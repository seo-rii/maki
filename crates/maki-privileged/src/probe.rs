//! Pure parsers for what the Linux executor observes (review M-006 /
//! M-016). Keeping them free of I/O makes the mount-identity and device
//! allocation logic testable on every platform; `exec` only feeds them
//! file contents.

/// What `/proc/self/mountinfo` says about one mountpoint. The mountpoint
/// is matched by its exact bytes; these fields are decoded lossily.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MountEntry {
    /// Chosen by whoever mounted (a FUSE `fsname` can be anything): a probe
    /// hint only, never identity.
    pub source: String,
    pub fstype: String,
    /// The mounted block device's `major:minor` (field 3), the handle
    /// for walking its sysfs topology.
    pub major_minor: String,
    /// The per-mount options (field 6), e.g. `rw`, `nosuid`, `nodev`.
    pub mount_options: Vec<String>,
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
        // A stack deeper than this is not a real block-device topology.
        // Fail *closed*: return no leaves so the caller refuses, exactly as
        // `detach.rs::depends_only_on` errors on the same condition. Dropping
        // only the over-deep subtree (an earlier bug) would hide a foreign
        // leaf below the bound while still returning the shallow NBD leaf,
        // letting `verify_mount_device` pass on an incomplete picture (F02).
        if depth > MAX_DEPTH {
            return Vec::new();
        }
        // A diamond (a device reached by more than one path) is normal and is
        // simply not re-walked; only the depth bound above is a resolution
        // failure.
        if !seen.insert(device.clone()) {
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

// `/proc/self/mountinfo` is bytes, not UTF-8 text. Linux escapes only
// space, tab, newline and backslash in its fields (`\040`, `\011`, `\012`,
// `\134`) and emits every other byte as is, so a path, source or FUSE
// subtype chosen by whoever mounted it can hold any non-UTF-8 sequence. The
// parsers below split and compare bytes: such a mount can neither make an
// observation fail nor be decoded into a configured path or hide a mount
// below one.

/// The table's records, split exactly as `str::lines` splits text: on
/// `\n`, dropping one `\r` before it.
pub(crate) fn mountinfo_lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split_inclusive(|&byte| byte == b'\n')
        .map(|line| match line.strip_suffix(b"\n") {
            Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
            None => line,
        })
}

/// Split a record at its first ` - `: mount fields (including the
/// optional ones) before it, filesystem fields after it. Paths cannot
/// contain the separator because their spaces are escaped.
pub(crate) fn split_record(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let at = line.windows(3).position(|window| window == b" - ")?;
    Some((&line[..at], &line[at + 3..]))
}

/// Decode the octal escapes mountinfo uses (`\040` for a space, ...) into
/// the field's exact bytes.
pub(crate) fn unescape(field: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(field.len());
    let mut i = 0;
    while i < field.len() {
        if let [b'\\', a @ b'0'..=b'3', b @ b'0'..=b'7', c @ b'0'..=b'7', ..] = field[i..] {
            out.push(((a - b'0') << 6) | ((b - b'0') << 3) | (c - b'0'));
            i += 4;
            continue;
        }
        out.push(field[i]);
        i += 1;
    }
    out
}

/// Mountinfo fields are separated by ASCII spaces. Linux escapes spaces,
/// tabs, newlines and backslashes inside paths, but preserves other whitespace
/// (including Unicode, carriage return and form-feed) as part of the field.
pub(crate) fn mountinfo_fields(record: &[u8]) -> impl Iterator<Item = &[u8]> {
    record
        .split(|&byte| byte == b' ')
        .filter(|field| !field.is_empty())
}

/// The comma-separated options of a per-mount or superblock options field.
pub(crate) fn mount_options(field: &[u8]) -> impl Iterator<Item = &[u8]> {
    field.split(|&byte| byte == b',')
}

/// Text for a field that is reported, never matched against a path: it is
/// only compared with ASCII constants (`xfs`, `nosuid`) or used as a probe
/// hint, so a replacement character can only make such a comparison fail.
fn lossy(field: &[u8]) -> String {
    String::from_utf8_lossy(field).into_owned()
}

/// Find the entry mounted exactly at `mountpoint`, comparing the unescaped
/// path bytes. When a path is mounted more than once the *last* line wins
/// (it is the visible mount).
pub fn parse_mountinfo(text: &(impl AsRef<[u8]> + ?Sized), mountpoint: &str) -> Option<MountEntry> {
    let mut found = None;
    for line in mountinfo_lines(text.as_ref()) {
        // id parent major:minor root mountpoint options [optional...] - fstype source superopts
        let Some((left, right)) = split_record(line) else {
            continue;
        };
        let left: Vec<&[u8]> = mountinfo_fields(left).collect();
        if left.len() < 6 {
            continue;
        }
        if unescape(left[4]) != mountpoint.as_bytes() {
            continue;
        }
        let right: Vec<&[u8]> = mountinfo_fields(right).collect();
        if right.len() < 2 {
            continue;
        }
        found = Some(MountEntry {
            fstype: lossy(right[0]),
            source: lossy(&unescape(right[1])),
            major_minor: lossy(left[2]),
            mount_options: mount_options(left[5]).map(lossy).collect(),
        });
    }
    found
}

/// Index of a `/dev/nbdN` device.
pub fn nbd_index(device: &str) -> Option<u32> {
    // Canonical spelling only (`/dev/nbd1`, never `/dev/nbd01` or `+1`):
    // identity checks compare device names as strings.
    let rest = device.strip_prefix("/dev/nbd")?;
    if rest.is_empty()
        || !rest.bytes().all(|b| b.is_ascii_digit())
        || (rest.len() > 1 && rest.starts_with('0'))
    {
        return None;
    }
    // nbd_genl_connect limits the index to MINORMASK >> part_shift. Even
    // with partitions disabled a Linux block device has only 20 minor bits.
    rest.parse::<u32>().ok().filter(|&index| index < (1 << 20))
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
