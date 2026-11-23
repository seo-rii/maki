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
    use sha2::{Digest, Sha256};
    use std::ffi::OsString;
    use std::io::{BufRead, BufReader, Read};
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

    /// The fields of one record admission reads, still escaped.
    struct MountRecord<'a> {
        root: &'a [u8],
        mountpoint: &'a [u8],
        fstype: &'a [u8],
    }

    /// Split a record into its fields by the positions Linux's
    /// `show_mountinfo` writes them: `id parent major:minor root mountpoint
    /// options [optional...] - fstype source superopts`. One ASCII space
    /// separates fields: Linux escapes the spaces inside paths, the type
    /// and the source (`\040`; tabs, newlines and backslashes too in paths),
    /// and other bytes, including Unicode whitespace, carriage return,
    /// form-feed and sequences that are not UTF-8, are field data. No field
    /// before the separator is ever empty. After it come exactly the type,
    /// the source and the superblock options, and only the source can be
    /// empty (when the string given to mount(2) was): that is the one way
    /// the kernel writes two consecutive spaces.
    fn mount_record(line: &[u8]) -> Result<MountRecord<'_>, String> {
        let Some(at) = line.windows(3).position(|window| window == b" - ") else {
            return Err("malformed mountinfo".into());
        };
        record_fields(&line[..at], &line[at + 3..])
            .ok_or_else(|| "malformed mountinfo fields".into())
    }

    fn record_fields<'a>(mount: &'a [u8], filesystem: &'a [u8]) -> Option<MountRecord<'a>> {
        let mut mount = mount.split(|&byte| byte == b' ');
        if mount.clone().any(<[u8]>::is_empty) {
            return None;
        }
        // id parent major:minor root mountpoint options [optional...]
        let (root, mountpoint) = (mount.nth(3)?, mount.next()?);
        let _options = mount.next()?;
        let mut filesystem = filesystem.splitn(3, |&byte| byte == b' ');
        let (fstype, _source) = (filesystem.next()?, filesystem.next()?);
        let super_options = filesystem.next()?;
        (!fstype.is_empty() && !super_options.is_empty()).then_some(MountRecord {
            root,
            mountpoint,
            fstype,
        })
    }

    const MOUNTINFO: &str = "/proc/self/mountinfo";

    /// The longest mount table record admission reads, newline included.
    /// A record holds two escaped paths, a type, a source and option lists.
    /// The table as a whole is not bounded: its size is host state, one
    /// record per mount. 1 MiB was the bound on the whole table before it
    /// was read as a stream, so no table accepted then is refused now.
    const MAX_MOUNTINFO_RECORD: u64 = 1 << 20;

    /// SHA-256 of every byte of one read of the mount table: two reads with
    /// the same digest read the same table.
    type TableDigest = [u8; 32];

    /// What one pass over the mount table found.
    struct MountScan {
        /// The first cgroup-v2 mountpoint, validated as a path admission
        /// resolves, and how many cgroup-v2 records there are.
        cgroup_mount: Option<PathBuf>,
        cgroup_mounts: usize,
        digest: TableDigest,
    }

    fn open_mountinfo<K: Kernel>(kernel: &K) -> Result<BufReader<K::Proc>, String> {
        kernel.open_proc(Path::new(MOUNTINFO)).map(BufReader::new)
    }

    /// Read the mount table as a stream of records, split as `str::lines`
    /// splits text, and check every record. The table is bytes, not text:
    /// only the cgroup-v2 records are decoded and validated as paths
    /// admission uses. With `cgroup_mount`, a mount at or below it refuses.
    fn scan_mountinfo(
        table: &mut impl BufRead,
        cgroup_mount: Option<&Path>,
    ) -> Result<MountScan, String> {
        let mut digest = Sha256::new();
        let mut scan = MountScan {
            cgroup_mount: None,
            cgroup_mounts: 0,
            digest: TableDigest::default(),
        };
        let mut line = Vec::new();
        loop {
            line.clear();
            table
                .by_ref()
                .take(MAX_MOUNTINFO_RECORD + 1)
                .read_until(b'\n', &mut line)
                .map_err(|e| format!("cannot read {MOUNTINFO}: {e}"))?;
            if line.is_empty() {
                break;
            }
            if line.len() as u64 > MAX_MOUNTINFO_RECORD {
                return Err(format!("oversized record in {MOUNTINFO}"));
            }
            digest.update(&line);
            let record = match line.strip_suffix(b"\n") {
                Some(record) => record.strip_suffix(b"\r").unwrap_or(record),
                None => &line,
            };
            let record = mount_record(record)?;
            if record.fstype != b"cgroup2" {
                let path = other_mount_path(record.mountpoint)?;
                if cgroup_mount.is_some_and(|mount| path.starts_with(mount)) {
                    return Err("nested mount can shadow cgroup memory policy".into());
                }
                continue;
            }
            let root = cgroup_mount_path(record.root)?;
            if root != Path::new("/") {
                return Err("subtree cgroup mount hides ancestor limits".into());
            }
            let mount = cgroup_mount_path(record.mountpoint)?;
            scan.cgroup_mount.get_or_insert(mount);
            scan.cgroup_mounts += 1;
        }
        scan.digest = digest.finalize().into();
        Ok(scan)
    }

    /// Resolve the leaf cgroup from the membership and the mount table,
    /// which `open` reads from its start on each call. The cgroup-v2
    /// record can follow a mount that shadows it, so a second pass checks
    /// every other mountpoint against it; the digests prove that both
    /// passes read the same table. Returns the table's digest for the
    /// recheck after the controller files are read.
    pub(super) fn layout<R: BufRead>(
        membership: &str,
        mut open: impl FnMut() -> Result<R, String>,
    ) -> Result<(Layout, TableDigest), String> {
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
        let first = scan_mountinfo(&mut open()?, None)?;
        let (Some(mount), 1) = (first.cgroup_mount, first.cgroup_mounts) else {
            return Err("missing or ambiguous cgroup-v2 mount".into());
        };
        if scan_mountinfo(&mut open()?, Some(&mount))?.digest != first.digest {
            return Err("kernel memory policy changed during admission".into());
        }
        let leaf = mount.join(group.strip_prefix("/").map_err(|_| "invalid cgroup path")?);
        Ok((Layout { mount, leaf }, first.digest))
    }

    fn open_nofollow(path: &Path) -> Result<std::fs::File, String> {
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|e| format!("cannot read {}: {e}", path.display()))
    }

    fn read_bounded_bytes(path: &Path, max: u64) -> Result<Vec<u8>, String> {
        read_bounded_from(open_nofollow(path)?, path, max)
    }

    /// Read `path`, already opened as `file`, refusing more than `max` bytes.
    fn read_bounded_from(file: impl Read, path: &Path, max: u64) -> Result<Vec<u8>, String> {
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
        utf8(read_bounded_bytes(path, max)?, path)
    }

    fn utf8(bytes: Vec<u8>, path: &Path) -> Result<String, String> {
        String::from_utf8(bytes).map_err(|_| {
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

    const PROC_CGROUP: &str = "/proc/self/cgroup";

    /// The kernel state admission reads besides the controller files, which
    /// `assess` reads under the resolved mount. The daemon reads the live
    /// kernel; tests substitute state that changes while admission runs.
    pub(super) trait Kernel {
        type Proc: Read;
        /// Open this process's `PROC_CGROUP` or `MOUNTINFO`.
        fn open_proc(&self, path: &Path) -> Result<Self::Proc, String>;
        /// The soft `RLIMIT_MEMLOCK`.
        fn memlock_limit(&self) -> Result<u64, String>;
        /// Refuse a resolved mount that is not a cgroup-v2 filesystem.
        fn check_cgroup2(&self, mount: &Path) -> Result<(), String>;
    }

    /// This process's procfs files and resource limit, and the real mount.
    struct LiveKernel;

    impl Kernel for LiveKernel {
        type Proc = std::fs::File;

        fn open_proc(&self, path: &Path) -> Result<std::fs::File, String> {
            open_nofollow(path)
        }

        fn memlock_limit(&self) -> Result<u64, String> {
            memlock_limit()
        }

        fn check_cgroup2(&self, mount: &Path) -> Result<(), String> {
            let file =
                std::fs::File::open(mount).map_err(|e| format!("cannot open cgroup mount: {e}"))?;
            let mut stat = std::mem::MaybeUninit::<libc::statfs>::uninit();
            // SAFETY: a live descriptor and correctly-sized writable statfs output.
            if unsafe { libc::fstatfs(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
                return Err("cannot identify cgroup filesystem".into());
            }
            // SAFETY: successful fstatfs initialized every field.
            if unsafe { stat.assume_init() }.f_type != libc::CGROUP2_SUPER_MAGIC {
                return Err("resolved mount is not a cgroup-v2 filesystem".into());
            }
            Ok(())
        }
    }

    /// Read one of this process's procfs files through `kernel`.
    fn read_proc(kernel: &impl Kernel, path: &str) -> Result<Vec<u8>, String> {
        let path = Path::new(path);
        read_bounded_from(kernel.open_proc(path)?, path, 1 << 20)
    }

    pub(super) fn verify(budget: &MemoryBudgetSection) -> Result<MemoryBudgetPosture, String> {
        verify_with(budget, &LiveKernel)
    }

    pub(super) fn verify_with(
        budget: &MemoryBudgetSection,
        kernel: &impl Kernel,
    ) -> Result<MemoryBudgetPosture, String> {
        let memlock = kernel.memlock_limit()?;
        if memlock < budget.required_memlock_bytes.0 {
            return Err("RLIMIT_MEMLOCK is below required_memlock_bytes".into());
        }
        let membership = utf8(read_proc(kernel, PROC_CGROUP)?, Path::new(PROC_CGROUP))?;
        // Linux emits mount path bytes as is: the table is never decoded.
        let (layout, mounts) = layout(&membership, || open_mountinfo(kernel))?;
        kernel.check_cgroup2(&layout.mount)?;
        let posture = assess(budget, &layout, memlock)?;
        if utf8(read_proc(kernel, PROC_CGROUP)?, Path::new(PROC_CGROUP))? != membership
            || scan_mountinfo(&mut open_mountinfo(kernel)?, None)?.digest != mounts
            || kernel.memlock_limit()? != memlock
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

    /// `layout` over a table in memory, which every pass reads from its
    /// start.
    fn layout(membership: &str, table: &(impl AsRef<[u8]> + ?Sized)) -> Result<Layout, String> {
        linux::layout(membership, || Ok(table.as_ref())).map(|(layout, _)| layout)
    }

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
    fn records_with_other_empty_fields_still_refuse() {
        // Only the source field can be empty. Any other empty field, or a
        // missing filesystem field, is not a record the kernel wrote: it
        // could shift a mountpoint and hide a nested mount.
        let cgroup = mountinfo("/", "/sys/fs/cgroup");
        for record in [
            "44 31 0:55 /  /srv rw - tmpfs tmpfs rw\n",
            "44 31 0:55 / /srv  rw - tmpfs tmpfs rw\n",
            "44 31 0:55 / /srv rw  - tmpfs tmpfs rw\n",
            " 44 31 0:55 / /srv rw - tmpfs tmpfs rw\n",
            "44 31 0:55 / /srv rw -  tmpfs rw\n",
            "44 31 0:55 / /srv rw - tmpfs tmpfs \n",
            "44 31 0:55 / /srv rw - tmpfs  \n",
            "44 31 0:55 / /srv rw - tmpfs tmpfs\n",
        ] {
            assert_eq!(
                layout("0::/slice/daemon\n", &format!("{cgroup}{record}")).unwrap_err(),
                "malformed mountinfo fields",
                "{record:?}"
            );
        }
    }

    #[test]
    fn the_mount_table_is_read_as_a_stream_of_bounded_records() {
        let membership = "0::/slice/daemon\n";
        let cgroup = mountinfo("/", "/sys/fs/cgroup");
        let expected = Layout {
            mount: "/sys/fs/cgroup".into(),
            leaf: "/sys/fs/cgroup/slice/daemon".into(),
        };
        // The table's size is host state: 4 MiB of other mounts, with the
        // cgroup-v2 record in the middle, read from a file as admission
        // reads the kernel's.
        let name = "m".repeat(200);
        let records: Vec<String> = (100..20_000)
            .map(|id| {
                format!("{id} 31 0:55 /source /srv/{name}{id} rw,relatime - tmpfs tmpfs rw\n")
            })
            .collect();
        let (before, after) = records.split_at(records.len() / 2);
        let table = [before.concat(), cgroup.clone(), after.concat()].concat();
        assert!(table.len() > 4 << 20);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("mountinfo");
        std::fs::write(&path, &table).unwrap();
        let open = || {
            std::fs::File::open(&path)
                .map(std::io::BufReader::new)
                .map_err(|e| e.to_string())
        };
        assert_eq!(
            linux::layout(membership, open).map(|(layout, _)| layout),
            Ok(expected)
        );

        // Only a record is bounded, its newline included.
        let record = |len: usize| {
            let (head, tail) = ("44 31 0:55 / /", " rw - tmpfs tmpfs rw\n");
            format!("{head}{}{tail}", "d".repeat(len - head.len() - tail.len()))
        };
        assert!(layout(membership, &format!("{cgroup}{}", record(1 << 20))).is_ok());
        for table in [
            format!("{cgroup}{}", record((1 << 20) + 1)),
            format!("{}{cgroup}", record((1 << 20) + 1)),
            format!("{cgroup}{}", record((1 << 20) + 2).trim_end()),
        ] {
            assert_eq!(
                layout(membership, &table).unwrap_err(),
                "oversized record in /proc/self/mountinfo"
            );
        }
    }

    #[test]
    fn every_pass_reads_and_checks_the_same_whole_table() {
        let membership = "0::/slice/daemon\n";
        let cgroup = mountinfo("/", "/sys/fs/cgroup");
        // A mount listed before the cgroup-v2 record still shadows it: the
        // second pass checks every mountpoint against the cgroup mount.
        let shadow = "44 31 0:55 / /sys/fs/cgroup/slice rw - tmpfs tmpfs rw\n";
        assert_eq!(
            layout(membership, &format!("{shadow}{cgroup}")).unwrap_err(),
            "nested mount can shadow cgroup memory policy"
        );

        // Both passes must read the same table.
        let other = "45 31 0:56 / /srv rw - tmpfs tmpfs rw\n";
        let table = format!("{cgroup}{other}");
        for (second, error) in [
            (
                format!("{cgroup}{}", other.replace("45 ", "46 ")),
                "kernel memory policy changed during admission",
            ),
            (
                format!("{shadow}{cgroup}"),
                "nested mount can shadow cgroup memory policy",
            ),
            (
                cgroup.clone(),
                "kernel memory policy changed during admission",
            ),
        ] {
            let mut reads = [table.as_bytes(), second.as_bytes()].into_iter();
            let result = linux::layout(membership, || Ok(reads.next().unwrap()));
            assert_eq!(result.unwrap_err(), error, "{second}");
        }

        // The digest the recheck compares is the table's exact bytes: equal
        // tables agree, and a difference the parser ignores still counts.
        let digest = |table: &str| {
            linux::layout(membership, || Ok(table.as_bytes()))
                .unwrap()
                .1
        };
        assert_eq!(digest(&table), digest(&table.clone()));
        assert_ne!(digest(&table), digest(&table.replace("45 ", "46 ")));
        assert_ne!(digest(&table), digest(&table.replace('\n', "\r\n")));
        assert_ne!(digest(&table), digest(table.trim_end()));
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

    /// Kernel state that changes when admission checks the resolved mount's
    /// filesystem: after the membership, mount table and resource limit
    /// were first read, before the controller files and the recheck.
    struct ChangingKernel {
        membership: [String; 2],
        mountinfo: [String; 2],
        memlock: [u64; 2],
        changed: std::cell::Cell<bool>,
    }

    impl ChangingKernel {
        fn new(membership: &str, mountinfo: &str, memlock: u64) -> Self {
            Self {
                membership: [membership.into(), membership.into()],
                mountinfo: [mountinfo.into(), mountinfo.into()],
                memlock: [memlock, memlock],
                changed: Default::default(),
            }
        }

        fn now(&self) -> usize {
            usize::from(self.changed.get())
        }
    }

    impl Kernel for ChangingKernel {
        type Proc = std::io::Cursor<Vec<u8>>;

        fn open_proc(&self, path: &Path) -> Result<Self::Proc, String> {
            let text = match path.to_str() {
                Some("/proc/self/cgroup") => &self.membership[self.now()],
                Some("/proc/self/mountinfo") => &self.mountinfo[self.now()],
                _ => panic!("unexpected kernel file {}", path.display()),
            };
            Ok(std::io::Cursor::new(text.clone().into_bytes()))
        }

        fn memlock_limit(&self) -> Result<u64, String> {
            Ok(self.memlock[self.now()])
        }

        fn check_cgroup2(&self, _mount: &Path) -> Result<(), String> {
            self.changed.set(true);
            Ok(())
        }
    }

    #[test]
    fn recheck_refuses_membership_mount_table_and_memlock_changed_during_admission() {
        let f = Fixture::new();
        let membership = "0::/slice/service\n";
        let table = mountinfo("/", f.layout.mount.to_str().unwrap());
        let posture = verify_with(&budget(), &ChangingKernel::new(membership, &table, 2048))
            .expect("unchanged kernel state is admitted");
        assert_eq!(posture.cgroup, f.layout.leaf);
        assert_eq!(posture.available_bytes, 3072);

        let mut moved = ChangingKernel::new(membership, &table, 2048);
        moved.membership[1] = "0::/slice/other\n".into();
        let mut remounted = ChangingKernel::new(membership, &table, 2048);
        remounted.mountinfo[1] = format!("{table}44 31 0:55 / /srv rw - tmpfs tmpfs rw\n");
        let mut relimited = ChangingKernel::new(membership, &table, 2048);
        relimited.memlock[1] = 4096;
        for (what, kernel) in [
            ("cgroup membership", moved),
            ("mount table", remounted),
            ("RLIMIT_MEMLOCK", relimited),
        ] {
            assert_eq!(
                verify_with(&budget(), &kernel).expect_err(what),
                "kernel memory policy changed during admission",
                "{what}"
            );
        }
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
