//! Admission requires an explicit measured budget and matching kernel policy.
use maki_nbdkit::daemon::parse_and_validate;

fn config(mode: &str, budget: &str) -> String {
    format!(
        r#"
config_schema_version = 1
[volume]
name = "memory-policy"
max_virtual_size = "1MiB"
[crypto]
provider = "local-aes-gcm-siv"
crypto_compatibility_id = "v1"
key = {{ source = "env", name = "unused" }}
[crypto.capabilities]
supported_plaintext_sizes = [4096]
max_ciphertext_size = 4384
[backing]
root = "/unused"
[cache]
lock_memory = false
[security]
memory_lock_mode = "{mode}"
{budget}
"#
    )
}

#[test]
fn explicit_measured_memory_budget_is_accepted() {
    parse_and_validate(&config(
        "secure-buffers",
        r#"
[security.memory_budget]
max_bytes = "256MiB"
startup_headroom_bytes = "16MiB"
required_memlock_bytes = "32MiB"
"#,
    ))
    .unwrap();
}

#[test]
fn memory_budget_rejects_missing_unknown_zero_and_inconsistent_limits() {
    for budget in [
        "max_bytes = 256",
        "max_bytes = 0\nstartup_headroom_bytes = 1\nrequired_memlock_bytes = 1",
        "max_bytes = 256\nstartup_headroom_bytes = 0\nrequired_memlock_bytes = 1",
        "max_bytes = 256\nstartup_headroom_bytes = 256\nrequired_memlock_bytes = 1",
        "max_bytes = 256\nstartup_headroom_bytes = 1\nrequired_memlock_bytes = 0",
        "max_bytes = 256\nstartup_headroom_bytes = 1\nrequired_memlock_bytes = 1\nunknown = 1",
    ] {
        assert!(
            parse_and_validate(&config(
                "secure-buffers",
                &format!("[security.memory_budget]\n{budget}")
            ))
            .is_err(),
            "{budget}"
        );
    }
    let budget = "[security.memory_budget]\nmax_bytes = 256\nstartup_headroom_bytes = 16\nrequired_memlock_bytes = 128";
    assert!(parse_and_validate(&config("all", budget)).is_err());
    assert!(parse_and_validate(&config("off", budget)).is_err());
    parse_and_validate(&config("all", &budget.replace("= 128", "= 256"))).unwrap();
    parse_and_validate(&config("off", &budget.replace("= 128", "= 0"))).unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn budget_failure_precedes_hardening_backing_recovery_and_credentials() {
    let cfg = parse_and_validate(&config("off", "[security.memory_budget]\nmax_bytes = 2\nstartup_headroom_bytes = 1\nrequired_memlock_bytes = 0")).unwrap();
    // A two-byte ceiling cannot match a page-granular Linux memory.max.
    // The backing and credential references are deliberately unavailable.
    let before = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
    let error = match maki_nbdkit::daemon::attach_from_config(&cfg).await {
        Ok(_) => panic!("mismatched memory budget reached attach"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("security.memory_budget"), "{error}");
    assert_eq!(
        unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) },
        before
    );
    assert!(maki_nbdkit::security::posture().is_none());
}

/// The disruptive kernel gate is opt-in and confines all writes to a newly
/// created child of an explicitly supplied delegated test cgroup.
#[cfg(all(target_os = "linux", feature = "cgroup-qualification"))]
#[test]
#[ignore = "requires MAKI_MEMORY_TEST_CGROUP with delegated memory controller"]
fn delegated_cgroup_oom_enforces_memory_max() {
    use std::os::unix::process::ExitStatusExt;
    use std::path::PathBuf;
    const CHILD: &str = "MAKI_MEMORY_OOM_CHILD";
    if let Some(path) = std::env::var_os(CHILD) {
        let path = PathBuf::from(path);
        std::fs::write(path.join("cgroup.procs"), std::process::id().to_string()).unwrap();
        let cfg = parse_and_validate(&config("off", "[security.memory_budget]\nmax_bytes = 33554432\nstartup_headroom_bytes = 1048576\nrequired_memlock_bytes = 0")).unwrap();
        assert_eq!(
            maki_nbdkit::security::memory::verify(&cfg)
                .unwrap()
                .unwrap()
                .max_bytes,
            33554432
        );
        // SAFETY: alarm bounds a kernel qualification child; SIGALRM is a test
        // failure, not the expected cgroup SIGKILL.
        unsafe {
            libc::alarm(20);
        }
        // Anonymous pages are faulted in after joining the disposable cgroup.
        // mmap avoids Rust allocator OOM handlers obscuring the kernel signal.
        let bytes = 128usize << 20;
        // SAFETY: private anonymous mapping; each volatile write stays in range.
        unsafe {
            let ptr = libc::mmap(
                std::ptr::null_mut(),
                bytes,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            assert_ne!(ptr, libc::MAP_FAILED);
            for offset in (0..bytes).step_by(4096) {
                (ptr as *mut u8).add(offset).write_volatile(1);
            }
            libc::munmap(ptr, bytes);
        }
        panic!("memory.max did not kill the allocating child");
    }
    let parent = PathBuf::from(
        std::env::var_os("MAKI_MEMORY_TEST_CGROUP")
            .expect("provide an already delegated disposable test cgroup"),
    );
    assert!(parent.is_absolute());
    assert_eq!(
        parent.canonicalize().unwrap(),
        parent,
        "no symlinked delegation paths"
    );
    assert!(
        std::fs::read_to_string(parent.join("cgroup.subtree_control"))
            .unwrap()
            .split_whitespace()
            .any(|v| v == "memory")
    );
    let path = parent.join(format!(
        "maki-memory-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&path).unwrap();
    struct Cleanup(PathBuf);
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir(&self.0);
        }
    }
    let cleanup = Cleanup(path.clone());
    std::fs::write(path.join("memory.max"), "33554432\n").unwrap();
    std::fs::write(path.join("memory.swap.max"), "0\n").unwrap();
    let result = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "delegated_cgroup_oom_enforces_memory_max",
            "--ignored",
            "--nocapture",
        ])
        .env(CHILD, &path)
        .output()
        .unwrap();
    assert_eq!(
        result.status.signal(),
        Some(libc::SIGKILL),
        "child: {:?}: {}",
        result.status,
        String::from_utf8_lossy(&result.stderr)
    );
    let events = std::fs::read_to_string(path.join("memory.events")).unwrap();
    assert!(
        events
            .lines()
            .any(|line| line.split_once(' ').is_some_and(
                |(name, value)| name == "oom_kill" && value.parse::<u64>().unwrap_or(0) > 0
            )),
        "{events}"
    );
    std::fs::remove_dir(&path).unwrap();
    std::mem::forget(cleanup);
}
