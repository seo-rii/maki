//! Read-only admission against the Linux cgroup-v2 memory controller.
//! The kernel enforces charged-memory limits for the service cgroup, not RSS.

use crate::daemon::DaemonError;
use maki_format::config::VolumeConfig;
use std::path::PathBuf;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MemoryBudgetPosture {
    pub cgroup: PathBuf,
    pub max_bytes: u64,
    pub current_bytes: u64,
    pub available_bytes: u64,
    pub required_headroom_bytes: u64,
    pub memlock_soft_bytes: u64,
    pub required_memlock_bytes: u64,
    pub visible_ancestors: usize,
}

/// Re-read the kernel policy; this does not modify cgroups or resource limits.
pub fn verify(config: &VolumeConfig) -> Result<Option<MemoryBudgetPosture>, DaemonError> {
    let Some(budget) = &config.security.memory_budget else {
        return Ok(None);
    };
    #[cfg(target_os = "linux")]
    {
        linux::verify(budget)
            .map(Some)
            .map_err(|e| DaemonError::Unsupported(format!("security.memory_budget: {e}")))
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = budget;
        Err(DaemonError::Unsupported(
            "security.memory_budget requires Linux cgroup v2".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use maki_format::config::MemoryBudgetSection;
    use std::ffi::OsString;
    use std::io::Read;
    use std::os::fd::AsRawFd;
    use std::os::unix::ffi::OsStringExt;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Component, Path};

    #[derive(Debug, PartialEq, Eq)]
    pub(super) struct Layout {
        pub(super) mount: PathBuf,
        pub(super) leaf: PathBuf,
    }

    fn absolute_path(text: &str) -> Result<PathBuf, String> {
        if !text.starts_with('/')
            || text.contains('\0')
            || text.contains('\n')
            || (text != "/"
                && text[1..]
                    .split('/')
                    .any(|s| s.is_empty() || s == "." || s == ".."))
            || text.split('/').count() > 256
        {
            return Err("invalid or escaping cgroup path".into());
        }
        Ok(PathBuf::from(text))
    }

    /// Decode the escapes Linux writes into mountinfo paths (`\040` space,
    /// `\011` tab, `\012` newline, `\134` backslash) into the path's exact
    /// bytes. The kernel escapes nothing else in these fields, so any other
    /// backslash sequence is a malformed table.
    fn unescape_mount(bytes: &[u8]) -> Result<Vec<u8>, String> {
        let mut result = Vec::with_capacity(bytes.len());
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'\\' {
                let escaped = bytes
                    .get(i + 1..i + 4)
                    .ok_or("truncated mountinfo escape")?;
                result.push(match escaped {
                    b"040" => b' ',
                    b"011" => b'\t',
                    b"012" => b'\n',
                    b"134" => b'\\',
                    _ => return Err("invalid mountinfo escape".into()),
                });
                i += 4;
            } else {
                result.push(bytes[i]);
                i += 1;
            }
        }
        Ok(result)
    }

    /// A path of the cgroup-v2 mount record, which admission resolves and
    /// reads: it must decode to UTF-8 and pass `absolute_path`.
    fn cgroup_mount_path(field: &[u8]) -> Result<PathBuf, String> {
        let text =
            String::from_utf8(unescape_mount(field)?).map_err(|_| "non-UTF8 mountinfo path")?;
        absolute_path(&text)
    }

    /// The mountpoint of any other mount, kept as its exact bytes: it is
    /// only compared, component by component, with the cgroup-v2 mount.
    /// Every name the kernel can emit is accepted (bytes that are not
    /// UTF-8, an escaped newline, any depth), so a mount elsewhere in the
    /// namespace cannot refuse admission. A path the kernel never emits
    /// (relative, or with a NUL or an empty, `.` or `..` component) is a
    /// malformed table that could hide a nested mount, and refuses.
    fn other_mount_path(field: &[u8]) -> Result<PathBuf, String> {
        let path = unescape_mount(field)?;
        if path.first() != Some(&b'/')
            || path.contains(&0)
            || (path != b"/"
                && path[1..]
                    .split(|&byte| byte == b'/')
                    .any(|s| s.is_empty() || s == b"." || s == b".."))
        {
            return Err("invalid mountinfo mountpoint".into());
        }
        Ok(PathBuf::from(OsString::from_vec(path)))
    }

    /// Records of the mount table, split as `str::lines` splits text.
    fn mountinfo_records(table: &[u8]) -> impl Iterator<Item = &[u8]> {
        table
            .split_inclusive(|&byte| byte == b'\n')
            .map(|line| match line.strip_suffix(b"\n") {
                Some(line) => line.strip_suffix(b"\r").unwrap_or(line),
                None => line,
            })
    }

    fn mountinfo_fields(part: &[u8]) -> Vec<&[u8]> {
        part.split(|&byte| byte == b' ')
            .filter(|field| !field.is_empty())
            .collect()
    }

    /// The mount table is bytes, not text: only the cgroup-v2 records are
    /// decoded and validated as paths admission uses.
    pub(super) fn layout(
        membership: &str,
        mountinfo: &(impl AsRef<[u8]> + ?Sized),
    ) -> Result<Layout, String> {
        let mut group = None;
        // procfs terminates records with LF; a preceding CR belongs to the path.
        for line in membership.split_terminator('\n') {
            let mut fields = line.splitn(3, ':');
            let id = fields.next().ok_or("malformed cgroup membership")?;
            let controllers = fields.next().ok_or("malformed cgroup membership")?;
            let path = fields.next().ok_or("malformed cgroup membership")?;
            if id.is_empty()
                || !id.bytes().all(|c| c.is_ascii_digit())
                || id.parse::<u32>().is_err()
            {
                return Err("malformed cgroup hierarchy identifier".into());
            }
            absolute_path(path)?;
            if id == "0" {
                if !controllers.is_empty() || group.replace(path).is_some() {
                    return Err("ambiguous cgroup-v2 membership".into());
                }
            } else if controllers.is_empty() {
                return Err("malformed legacy cgroup membership".into());
            }
        }
        let group = group.ok_or("no cgroup-v2 membership")?;
        if group.ends_with(" (deleted)") || group == "/" {
            return Err("ambiguous, deleted or namespace-root cgroup membership".into());
        }
        let group = absolute_path(group)?;
        let mut mounts = Vec::new();
        let mut other_mounts = Vec::new();
        for line in mountinfo_records(mountinfo.as_ref()) {
            let Some(at) = line.windows(3).position(|window| window == b" - ") else {
                return Err("malformed mountinfo".into());
            };
            // Linux separates fields with ASCII spaces and escapes spaces,
            // tabs, newlines and backslashes within paths. Other bytes,
            // including Unicode whitespace, carriage return, form-feed and
            // sequences that are not UTF-8, are path data.
            let fields = mountinfo_fields(&line[..at]);
            let fs = mountinfo_fields(&line[at + 3..]);
            if fields.len() < 6 || fs.len() < 3 {
                return Err("malformed mountinfo fields".into());
            }
            if fs[0] != b"cgroup2" {
                other_mounts.push(other_mount_path(fields[4])?);
                continue;
            }
            let root = cgroup_mount_path(fields[3])?;
            if root != Path::new("/") {
                return Err("subtree cgroup mount hides ancestor limits".into());
            }
            mounts.push(cgroup_mount_path(fields[4])?);
        }
        if mounts.len() != 1 {
            return Err("missing or ambiguous cgroup-v2 mount".into());
        }
        let mount = mounts.remove(0);
        if other_mounts.iter().any(|other| other.starts_with(&mount)) {
            return Err("nested mount can shadow cgroup memory policy".into());
        }
        let leaf = mount.join(group.strip_prefix("/").map_err(|_| "invalid cgroup path")?);
        Ok(Layout { mount, leaf })
    }

    fn read_bounded_bytes(path: &Path, max: u64) -> Result<Vec<u8>, String> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        let mut result = Vec::new();
        file.take(max + 1)
            .read_to_end(&mut result)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))?;
        if result.len() as u64 > max {
            return Err(format!("oversized kernel field {}", path.display()));
        }
        Ok(result)
    }

    fn read_bounded(path: &Path, max: u64) -> Result<String, String> {
        String::from_utf8(read_bounded_bytes(path, max)?).map_err(|_| {
            format!(
                "cannot read {}: stream did not contain valid UTF-8",
                path.display()
            )
        })
    }

    fn number(value: &str) -> Result<u64, String> {
        let value = value.trim();
        if value.is_empty() || !value.bytes().all(|c| c.is_ascii_digit()) {
            return Err("malformed memory controller number".into());
        }
        value
            .parse()
            .map_err(|_| "memory controller number overflow".into())
    }

    pub(super) fn memlock_limit() -> Result<u64, String> {
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: valid writable rlimit, constant resource selector.
        if unsafe { libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut limit) } != 0 {
            return Err(format!(
                "cannot read RLIMIT_MEMLOCK: {}",
                std::io::Error::last_os_error()
            ));
        }
        if limit.rlim_cur == libc::RLIM_INFINITY {
            Ok(u64::MAX)
        } else {
            // rlim_t is u32 on some supported Linux ABIs and u64 on others.
            #[allow(clippy::unnecessary_cast)]
            let bytes = limit.rlim_cur as u64;
            Ok(bytes)
        }
    }

    pub(super) fn assess(
        budget: &MemoryBudgetSection,
        layout: &Layout,
        memlock: u64,
    ) -> Result<MemoryBudgetPosture, String> {
        if memlock < budget.required_memlock_bytes.0 {
            return Err("RLIMIT_MEMLOCK is below required_memlock_bytes".into());
        }
        if budget.startup_headroom_bytes.0 == 0
            || budget.startup_headroom_bytes.0 >= budget.max_bytes.0
        {
            return Err("invalid max_bytes/startup_headroom_bytes".into());
        }
        let relative = layout
            .leaf
            .strip_prefix(&layout.mount)
            .map_err(|_| "cgroup path escapes mount")?;
        if relative.as_os_str().is_empty()
            || relative
                .components()
                .any(|c| !matches!(c, Component::Normal(_)))
        {
            return Err("invalid leaf cgroup".into());
        }
        let mut available = u64::MAX;
        let mut current = 0;
        let mut ancestors = 0;
        for dir in layout.leaf.ancestors() {
            if !dir.starts_with(&layout.mount) {
                break;
            }
            if dir
                .canonicalize()
                .map_err(|e| format!("cannot resolve cgroup: {e}"))?
                != dir
            {
                return Err("symlinked cgroup directory".into());
            }
            let max_path = dir.join("memory.max");
            // The actual hierarchy root has no memory controller limits.
            if dir == layout.mount
                && std::fs::symlink_metadata(&max_path)
                    .is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound)
            {
                break;
            }
            let limit = read_bounded(&max_path, 128)?;
            let used = number(&read_bounded(&dir.join("memory.current"), 128)?)?;
            if dir == layout.leaf {
                if limit.trim() == "max" || number(&limit)? != budget.max_bytes.0 {
                    return Err("leaf memory.max must exactly match finite max_bytes".into());
                }
                current = used;
            } else {
                ancestors += 1;
            }
            if limit.trim() != "max" {
                let cap = number(&limit)?;
                if cap < budget.max_bytes.0 {
                    return Err("ancestor memory.max is smaller than configured max_bytes".into());
                }
                let remaining = cap
                    .checked_sub(used)
                    .ok_or("memory usage exceeds controller limit")?;
                available = available.min(remaining);
                if remaining < budget.startup_headroom_bytes.0 {
                    return Err("insufficient cgroup memory headroom".into());
                }
            }
        }
        Ok(MemoryBudgetPosture {
            cgroup: layout.leaf.clone(),
            max_bytes: budget.max_bytes.0,
            current_bytes: current,
            available_bytes: available,
            required_headroom_bytes: budget.startup_headroom_bytes.0,
            memlock_soft_bytes: memlock,
            required_memlock_bytes: budget.required_memlock_bytes.0,
            visible_ancestors: ancestors,
        })
    }

    pub(super) fn verify(budget: &MemoryBudgetSection) -> Result<MemoryBudgetPosture, String> {
        let memlock = memlock_limit()?;
        if memlock < budget.required_memlock_bytes.0 {
            return Err("RLIMIT_MEMLOCK is below required_memlock_bytes".into());
        }
        let membership = read_bounded(Path::new("/proc/self/cgroup"), 1 << 20)?;
        // Linux emits mount path bytes as is: the table is never decoded.
        let mounts = read_bounded_bytes(Path::new("/proc/self/mountinfo"), 1 << 20)?;
        let layout = layout(&membership, &mounts)?;
        let file = std::fs::File::open(&layout.mount)
            .map_err(|e| format!("cannot open cgroup mount: {e}"))?;
        let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
        // SAFETY: a live descriptor and correctly-sized writable statfs output.
        if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err("cannot identify cgroup filesystem".into());
        }
        // SAFETY: successful fstatfs initialized every field.
        if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
            return Err("resolved mount is not a cgroup-v2 filesystem".into());
        }
        let posture = assess(budget, &layout, memlock)?;
        if read_bounded(Path::new("/proc/self/cgroup"), 1 << 20)? != membership
            || read_bounded_bytes(Path::new("/proc/self/mountinfo"), 1 << 20)? != mounts
            || memlock_limit()? != memlock
        {
            return Err("kernel memory policy changed during admission".into());
        }
        Ok(posture)
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::*;
    use super::*;
    use maki_format::config::{ByteSize, MemoryBudgetSection};
    use std::path::Path;

    fn budget() -> MemoryBudgetSection {
        MemoryBudgetSection {
            max_bytes: ByteSize(4096),
            startup_headroom_bytes: ByteSize(1024),
            required_memlock_bytes: ByteSize(2048),
        }
    }

    fn mountinfo(root: &str, mount: &str) -> String {
        format!("31 22 0:26 {root} {mount} rw,nosuid shared:9 - cgroup2 cgroup2 rw\n")
    }

    struct Fixture {
        _dir: tempfile::TempDir,
        layout: Layout,
    }
    impl Fixture {
        fn new() -> Self {
            let dir = tempfile::tempdir().unwrap();
            let mount = dir.path().join("cgroup");
            let leaf = mount.join("slice/service");
            std::fs::create_dir_all(&leaf).unwrap();
            for p in [&leaf, &mount.join("slice")] {
                std::fs::write(p.join("memory.max"), "4096\n").unwrap();
                std::fs::write(p.join("memory.current"), "1024\n").unwrap();
            }
            Self {
                _dir: dir,
                layout: Layout { mount, leaf },
            }
        }
        fn write(&self, level: usize, file: &str, value: &str) {
            std::fs::write(
                self.layout.leaf.ancestors().nth(level).unwrap().join(file),
                value,
            )
            .unwrap();
        }
    }

    #[test]
    fn resolves_actual_membership_and_mountinfo_escaping() {
        let result = layout(
            "0::/system.slice/code-server\\x2dtest.service\n",
            &mountinfo("/", "/sys/fs/cgroup"),
        )
        .unwrap();
        assert_eq!(
            result.leaf,
            Path::new("/sys/fs/cgroup/system.slice/code-server\\x2dtest.service")
        );
        assert_eq!(
            layout("0::/slice/daemon\n", &mountinfo("/", "/test\\040mount"))
                .unwrap()
                .mount,
            Path::new("/test mount")
        );
        assert!(layout(
            "1:cpu,cpuacct:/legacy\n0::/slice/daemon\n",
            &mountinfo("/", "/sys/fs/cgroup")
        )
        .is_ok());
    }

    #[test]
    fn preserves_non_separator_whitespace_in_mountpoints_and_membership() {
        for whitespace in ['\u{00a0}', '\u{2003}', '\r', '\u{000c}'] {
            let mount = format!("/sys/fs/cgroup{whitespace}real");
            let group = format!("/slice/service{whitespace}name");
            let result = layout(&format!("0::{group}\n"), &mountinfo("/", &mount)).unwrap();
            assert_eq!(result.mount, Path::new(&mount));
            assert_eq!(result.leaf, Path::new(&format!("{mount}{group}")));
        }
    }

    #[test]
    fn preserves_trailing_carriage_returns_in_membership() {
        for group in ["/slice/service\r", "/slice/service\r\r"] {
            for ending in ["", "\n"] {
                let membership = format!("1:cpu:/legacy\r\n0::{group}{ending}");
                let result = layout(&membership, &mountinfo("/", "/sys/fs/cgroup")).unwrap();
                assert_eq!(result.leaf, Path::new(&format!("/sys/fs/cgroup{group}")));
            }
        }
    }

    #[test]
    fn admission_checks_carriage_return_named_leaf_instead_of_sibling() {
        let f = Fixture::new();
        let actual = f.layout.mount.join("slice/service\r");
        std::fs::create_dir(&actual).unwrap();
        std::fs::write(actual.join("memory.max"), "4096\n").unwrap();
        std::fs::write(actual.join("memory.current"), "4090\n").unwrap();
        f.write(1, "memory.max", "16384\n");
        f.write(1, "memory.current", "5114\n");
        assert_eq!(
            assess(&budget(), &f.layout, 2048).unwrap().available_bytes,
            3072
        );
        let expected = Layout {
            mount: f.layout.mount.clone(),
            leaf: actual,
        };
        assert_eq!(
            assess(&budget(), &expected, 2048).unwrap_err(),
            "insufficient cgroup memory headroom"
        );
        let parsed = layout(
            "0::/slice/service\r\n",
            &mountinfo("/", f.layout.mount.to_str().unwrap()),
        )
        .unwrap();
        assert_eq!(
            assess(&budget(), &parsed, 2048).unwrap_err(),
            "insufficient cgroup memory headroom"
        );
    }

    #[test]
    fn whitespace_in_a_sibling_mountpoint_does_not_shadow_cgroup_policy() {
        for whitespace in ['\u{00a0}', '\u{2003}', '\r', '\u{000c}'] {
            let mounts = format!(
                "{}44 31 0:55 / /sys/fs/cgroup{whitespace}backup rw - tmpfs tmpfs rw\n",
                mountinfo("/", "/sys/fs/cgroup")
            );
            let result = layout("0::/slice/daemon\n", &mounts).unwrap();
            assert_eq!(result.mount, Path::new("/sys/fs/cgroup"));
            assert_eq!(result.leaf, Path::new("/sys/fs/cgroup/slice/daemon"));
        }
    }

    #[test]
    fn whitespace_named_subtrees_are_not_the_cgroup_hierarchy_root() {
        for whitespace in ['\u{00a0}', '\u{2003}', '\r', '\u{000c}'] {
            let root = format!("/{whitespace}");
            let error =
                layout("0::/slice/daemon\n", &mountinfo(&root, "/sys/fs/cgroup")).unwrap_err();
            assert_eq!(error, "subtree cgroup mount hides ancestor limits");
        }
    }

    #[test]
    fn refuses_escaping_ambiguous_hidden_and_missing_hierarchies() {
        for membership in [
            "",
            "1:memory:/foo\n",
            "0::relative\n",
            "0::/../escape\n",
            "0::/a/./b\n",
            "0::/a//b\n",
            "0::/a (deleted)\n",
            "0::/a\n0::/b\n",
            "0::/a\nmalformed\n",
            "0::/a\n0:cpu:/b\n",
            "0::/\n",
        ] {
            assert!(
                layout(membership, &mountinfo("/", "/sys/fs/cgroup")).is_err(),
                "{membership:?}"
            );
        }
        for info in [
            mountinfo("/hidden", "/sys/fs/cgroup"),
            mountinfo("/", "/bad/../mount"),
            mountinfo("/", "/bad\\777mount"),
            mountinfo("/", "/sys/fs/cgroup").repeat(2),
            "31\t22\t0:26\t/\t/sys/fs/cgroup\trw - cgroup2 cgroup2 rw\n".into(),
            "31 22 0:26 / /sys/fs/cgroup rw - cgroup2\tcgroup2\trw\n".into(),
            String::new(),
        ] {
            assert!(layout("0::/slice/daemon\n", &info).is_err(), "{info}");
        }
    }

    #[test]
    fn refuses_non_cgroup_submounts_shadowing_kernel_policy() {
        let mounts = format!(
            "{}44 31 0:55 / /sys/fs/cgroup/slice/daemon/memory.max rw - tmpfs tmpfs rw\n",
            mountinfo("/", "/sys/fs/cgroup")
        );
        assert!(
            layout("0::/slice/daemon\n", &mounts).is_err(),
            "a shadow mount cannot supply kernel policy"
        );
    }

    #[test]
    fn whitespace_named_submounts_still_shadow_cgroup_policy() {
        for whitespace in ['\u{00a0}', '\u{2003}', '\r', '\u{000c}'] {
            let mounts = format!(
                "{}44 31 0:55 / /sys/fs/cgroup/slice{whitespace}child rw - tmpfs tmpfs rw\n",
                mountinfo("/", "/sys/fs/cgroup")
            );
            let error = layout("0::/slice/daemon\n", &mounts).unwrap_err();
            assert_eq!(error, "nested mount can shadow cgroup memory policy");
        }
    }

    #[test]
    fn unrelated_mount_path_bytes_do_not_refuse_admission() {
        // Linux escapes only space, tab, newline and backslash in mountinfo
        // paths and emits every other byte as is. A user's FUSE mount, a
        // Latin-1 USB label or a deep directory elsewhere in the namespace
        // is ordinary state, not a malformed cgroup hierarchy.
        let cgroup = mountinfo("/", "/sys/fs/cgroup").into_bytes();
        let tmpfs =
            |path: &[u8]| [b"44 31 0:55 / ".as_slice(), path, b" rw - tmpfs tmpfs rw\n"].concat();
        let deep = [b"/srv".as_slice(), &b"/d".repeat(300)].concat();
        let foreign = [
            (
                "path, FUSE subtype and source not UTF-8",
                b"52 31 0:61 / /home/user/fuse-\xff rw,nosuid,nodev - fuse.\xfe \xfd rw\n".to_vec(),
            ),
            ("escaped newline", tmpfs(b"/media/usb\\012stick")),
            ("301 components", tmpfs(&deep)),
            ("non-UTF-8 sibling", tmpfs(b"/sys/fs/cgroup\xff")),
            ("escaped newline sibling", tmpfs(b"/sys/fs/cgroup\\012")),
        ];
        let expected = Layout {
            mount: "/sys/fs/cgroup".into(),
            leaf: "/sys/fs/cgroup/slice/daemon".into(),
        };
        let all: Vec<u8> = foreign
            .iter()
            .flat_map(|(_, record)| record.clone())
            .collect();
        let mut refused = Vec::new();
        for (case, record) in foreign.iter().chain([&("all of them", all)]) {
            for (order, table) in [
                ("after", [cgroup.as_slice(), record].concat()),
                ("before", [record.as_slice(), &cgroup].concat()),
            ] {
                let result = layout("0::/slice/daemon\n", &table);
                if result.as_ref() != Ok(&expected) {
                    refused.push(format!("{case}, {order} the cgroup2 mount: {result:?}"));
                }
            }
        }
        assert!(refused.is_empty(), "{refused:#?}");
    }

    #[test]
    fn mounts_at_or_below_the_cgroup_mount_shadow_policy_whatever_their_bytes() {
        let cgroup = mountinfo("/", "/sys/fs/cgroup").into_bytes();
        let record = |fstype: &[u8], path: &[u8]| {
            let parts = [b"44 31 0:55 / ".as_slice(), path, b" rw - ", fstype];
            [cgroup.as_slice(), &parts.concat(), b" none rw\n"].concat()
        };
        // The root filesystem is a sibling of every hierarchy, not a parent.
        assert!(layout("0::/slice/daemon\n", &record(b"ext4", b"/")).is_ok());
        let deep = [b"/sys/fs/cgroup".as_slice(), &b"/d".repeat(300)].concat();
        for (fstype, path) in [
            (b"tmpfs".as_slice(), b"/sys/fs/cgroup".as_slice()),
            (b"tmpfs", b"/sys/fs/cgroup/slice/\xff"),
            (b"tmpfs", b"/sys/fs/cgroup/\xff/daemon"),
            (b"fuse.\xfe", b"/sys/fs/cgroup/slice/daemon"),
            (b"tmpfs", b"/sys/fs/cgroup/slice\\012daemon"),
            (b"tmpfs", &deep),
        ] {
            assert_eq!(
                layout("0::/slice/daemon\n", &record(fstype, path)).unwrap_err(),
                "nested mount can shadow cgroup memory policy",
                "{}",
                String::from_utf8_lossy(&path[..path.len().min(48)])
            );
        }
    }

    #[test]
    fn cgroup2_records_and_undecodable_mountpoints_still_refuse() {
        let cgroup = mountinfo("/", "/sys/fs/cgroup").into_bytes();
        let cgroup2 = |root: &[u8], mount: &[u8]| {
            [
                b"31 22 0:26 ".as_slice(),
                root,
                b" ",
                mount,
                b" rw - cgroup2 cgroup2 rw\n",
            ]
            .concat()
        };
        let tmpfs = |path: &[u8]| {
            [
                cgroup.as_slice(),
                b"44 31 0:55 / ",
                path,
                b" rw - tmpfs tmpfs rw\n",
            ]
            .concat()
        };
        let deep = [b"/sys/fs/cgroup".as_slice(), &b"/d".repeat(300)].concat();
        for (table, error) in [
            // The hierarchy's own record is still a UTF-8 cgroup path.
            (
                cgroup2(b"/", b"/sys/fs/cgroup-\xff"),
                "non-UTF8 mountinfo path",
            ),
            (
                cgroup2(b"/\xff", b"/sys/fs/cgroup"),
                "non-UTF8 mountinfo path",
            ),
            (
                cgroup2(b"/", b"/sys/fs/cgroup\\012"),
                "invalid or escaping cgroup path",
            ),
            (cgroup2(b"/", &deep), "invalid or escaping cgroup path"),
            (cgroup2(b"/", b"/sys/fs/\\777"), "invalid mountinfo escape"),
            // A second hierarchy is never skipped, whatever its path.
            (
                [cgroup.as_slice(), &cgroup2(b"/", b"/mnt/\xff")].concat(),
                "non-UTF8 mountinfo path",
            ),
            (
                [cgroup.as_slice(), &cgroup2(b"/", b"/mnt/second")].concat(),
                "missing or ambiguous cgroup-v2 mount",
            ),
            // Mountpoints the kernel never emits cannot be compared, so they
            // refuse rather than possibly hide a nested mount.
            (tmpfs(b"relative"), "invalid mountinfo mountpoint"),
            (tmpfs(b"/srv//x"), "invalid mountinfo mountpoint"),
            (tmpfs(b"/srv/./x"), "invalid mountinfo mountpoint"),
            (
                tmpfs(b"/srv/../sys/fs/cgroup/slice"),
                "invalid mountinfo mountpoint",
            ),
            (tmpfs(b"/srv/"), "invalid mountinfo mountpoint"),
            (tmpfs(b"/srv\0x"), "invalid mountinfo mountpoint"),
            (tmpfs(b"/srv\\777"), "invalid mountinfo escape"),
            (tmpfs(b"/srv\\000"), "invalid mountinfo escape"),
            (tmpfs(b"/srv\\04"), "truncated mountinfo escape"),
            (
                [cgroup.as_slice(), b"44 31 0:55 / /srv\xff rw tmpfs\n"].concat(),
                "malformed mountinfo",
            ),
            (
                [cgroup.as_slice(), b"44 31 0:55 / /srv\xff - tmpfs\n"].concat(),
                "malformed mountinfo fields",
            ),
        ] {
            assert_eq!(
                layout("0::/slice/daemon\n", &table).unwrap_err(),
                error,
                "{}",
                String::from_utf8_lossy(&table[..table.len().min(160)])
            );
        }
    }

    #[test]
    fn empty_mount_sources_are_empty_fields() {
        // Linux prints a mount whose source string is empty (`mount -t tmpfs
        // '' /dir`, a FUSE mount with an empty `fsname`) as an empty field,
        // the only place where it writes two consecutive spaces.
        let cgroup = mountinfo("/", "/sys/fs/cgroup");
        let empty = "52 31 0:61 / /run/empty rw,relatime - tmpfs  rw,mode=755\n";
        let expected = Layout {
            mount: "/sys/fs/cgroup".into(),
            leaf: "/sys/fs/cgroup/slice/daemon".into(),
        };
        for table in [
            format!("{cgroup}{empty}"),
            format!("{empty}{cgroup}{empty}"),
            "31 22 0:26 / /sys/fs/cgroup rw,nosuid shared:9 - cgroup2  rw\n".into(),
        ] {
            assert_eq!(
                layout("0::/slice/daemon\n", &table).as_ref(),
                Ok(&expected),
                "{table}"
            );
        }
        // Such a mount below the cgroup mount still shadows its policy.
        let nested = format!("{cgroup}44 31 0:55 / /sys/fs/cgroup/slice rw - tmpfs  rw\n");
        assert_eq!(
            layout("0::/slice/daemon\n", &nested).unwrap_err(),
            "nested mount can shadow cgroup memory policy"
        );
    }

    #[test]
    fn admission_uses_leaf_limit_and_all_visible_ancestor_headroom() {
        let f = Fixture::new();
        let result = assess(&budget(), &f.layout, 2048).unwrap();
        assert_eq!(result.current_bytes, 1024);
        assert_eq!(result.available_bytes, 3072);
        assert_eq!(result.visible_ancestors, 1);
        f.write(1, "memory.current", "3072\n");
        assert_eq!(
            assess(&budget(), &f.layout, u64::MAX)
                .unwrap()
                .available_bytes,
            1024
        );
        f.write(1, "memory.current", "3073\n");
        assert!(assess(&budget(), &f.layout, 2048)
            .unwrap_err()
            .contains("headroom"));
        f.write(1, "memory.max", "max\n");
        assert!(assess(&budget(), &f.layout, 2048).is_ok());
    }

    #[test]
    fn refuses_unlimited_mismatched_malformed_missing_overflow_and_low_memlock() {
        let f = Fixture::new();
        assert!(assess(&budget(), &f.layout, 2047)
            .unwrap_err()
            .contains("MEMLOCK"));
        for value in [
            "max\n",
            "4097\n",
            "0\n",
            "-1\n",
            "+4096\n",
            "4096 4096\n",
            "18446744073709551616\n",
            "",
        ] {
            f.write(0, "memory.max", value);
            assert!(assess(&budget(), &f.layout, 2048).is_err(), "{value:?}");
        }
        f.write(0, "memory.max", "4096\n");
        for value in [
            "max\n",
            "-1\n",
            "4097\n",
            "18446744073709551615\n",
            "garbage\n",
            "",
        ] {
            f.write(0, "memory.current", value);
            assert!(assess(&budget(), &f.layout, 2048).is_err(), "{value:?}");
        }
        f.write(0, "memory.current", "1024\n");
        f.write(1, "memory.max", "2048\n");
        assert!(
            assess(&budget(), &f.layout, 2048).is_err(),
            "stricter ancestor changes measured ceiling"
        );
        std::fs::remove_file(f.layout.leaf.parent().unwrap().join("memory.max")).unwrap();
        assert!(assess(&budget(), &f.layout, 2048).is_err());
    }

    #[test]
    fn recheck_refuses_headroom_consumed_after_recovery() {
        let f = Fixture::new();
        assert!(assess(&budget(), &f.layout, 2048).is_ok());
        f.write(0, "memory.current", "3073\n");
        assert!(assess(&budget(), &f.layout, 2048).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlinked_policy_files_and_directories() {
        use std::os::unix::fs::symlink;
        let f = Fixture::new();
        let max = f.layout.leaf.join("memory.max");
        std::fs::remove_file(&max).unwrap();
        symlink(f.layout.leaf.parent().unwrap().join("memory.max"), &max).unwrap();
        assert!(assess(&budget(), &f.layout, 2048).is_err());
    }

    #[test]
    fn actual_child_rlimit_memlock_is_enforced_without_affecting_parent() {
        const CHILD: &str = "MAKI_MEMORY_RLIMIT_CHILD";
        if std::env::var_os(CHILD).is_some() {
            let zero = libc::rlimit {
                rlim_cur: 0,
                rlim_max: 0,
            };
            // SAFETY: this is a freshly exec'd child; no parent limits change.
            assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &zero) }, 0);
            assert_eq!(memlock_limit().unwrap(), 0);
            assert!(linux::verify(&budget())
                .unwrap_err()
                .contains("RLIMIT_MEMLOCK"));
            return;
        }
        let before = memlock_limit().unwrap();
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "security::memory::tests::actual_child_rlimit_memlock_is_enforced_without_affecting_parent", "--nocapture"])
            .env(CHILD, "1").output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(memlock_limit().unwrap(), before);
    }

    #[test]
    fn actual_kernel_membership_and_unlimited_limit_are_not_substituted() {
        let membership = std::fs::read_to_string("/proc/self/cgroup").unwrap();
        let mounts = std::fs::read("/proc/self/mountinfo").unwrap();
        let result = layout(&membership, &mounts);
        let Ok(view) = result else {
            // Restricted container views are a deliberate fail-closed result.
            let error = linux::verify(&MemoryBudgetSection {
                max_bytes: ByteSize(4096),
                startup_headroom_bytes: ByteSize(1),
                required_memlock_bytes: ByteSize(0),
            })
            .unwrap_err();
            assert!(!error.is_empty());
            return;
        };
        let actual = std::fs::read_to_string(view.leaf.join("memory.max")).unwrap();
        // Deliberately mismatch a finite leaf, or reject the host's unlimited leaf.
        let configured = if actual.trim() == "max" {
            4096
        } else {
            actual.trim().parse::<u64>().unwrap().saturating_add(4096)
        };
        let error = linux::verify(&MemoryBudgetSection {
            max_bytes: ByteSize(configured),
            startup_headroom_bytes: ByteSize(1),
            required_memlock_bytes: ByteSize(0),
        })
        .unwrap_err();
        assert!(error.contains("leaf memory.max"), "{error}");
    }

    #[test]
    fn all_numeric_boundaries_and_ancestor_levels_preserve_admission_invariant() {
        let f = Fixture::new();
        for level in [0, 1] {
            for used in [0, 1, 1023, 1024, 3071, 3072, 3073, 4095, 4096, u64::MAX] {
                f.write(level, "memory.current", &format!("{used}\n"));
                assert_eq!(
                    assess(&budget(), &f.layout, 2048).is_ok(),
                    used <= 3072,
                    "level={level}, used={used}"
                );
            }
            f.write(level, "memory.current", "1024\n");
        }
        let huge = "x".repeat(129);
        f.write(0, "memory.current", &huge);
        assert!(assess(&budget(), &f.layout, 2048)
            .unwrap_err()
            .contains("oversized"));
    }

    #[test]
    fn nested_hierarchy_and_unknown_ancestor_usage_fail_closed() {
        let f = Fixture::new();
        let nested = f.layout.leaf.join("nested");
        std::fs::create_dir(&nested).unwrap();
        std::fs::write(nested.join("memory.max"), "4096\n").unwrap();
        std::fs::write(nested.join("memory.current"), "1024\n").unwrap();
        let layout = Layout {
            mount: f.layout.mount.clone(),
            leaf: nested,
        };
        assert_eq!(
            assess(&budget(), &layout, 2048).unwrap().visible_ancestors,
            2
        );
        f.write(1, "memory.max", "max\n");
        std::fs::remove_file(f.layout.leaf.parent().unwrap().join("memory.current")).unwrap();
        assert!(assess(&budget(), &layout, 2048).is_err());
    }
}
