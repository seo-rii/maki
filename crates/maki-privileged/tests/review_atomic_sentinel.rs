//! Only the isolated plain-file sentinel path runs; no mount/LVM/NBD steps.
#![cfg(target_os = "linux")]
use maki_privileged::plan::{Plan, PlannedStep, SENTINEL_FILE};

#[test]
fn partial_sentinel_child() {
    let Ok(path) = std::env::var("MAKI_SENTINEL_PARTIAL_CHILD") else {
        return;
    };
    let uuid = "11111111-2222-3333-4444-555555555555";
    let plan = Plan {
        description: "plain-file sentinel test".into(),
        volume: "test".into(),
        attachment: None,
        steps: vec![PlannedStep::WriteSentinel {
            mountpoint: path.clone(),
            volume_uuid: uuid.into(),
        }],
    };
    unsafe {
        let mut original: libc::rlimit = std::mem::zeroed();
        assert_eq!(libc::getrlimit(libc::RLIMIT_FSIZE, &mut original), 0);
        let old_signal = libc::signal(libc::SIGXFSZ, libc::SIG_IGN);
        let limit = libc::rlimit {
            rlim_cur: 10,
            rlim_max: original.rlim_max,
        };
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &limit), 0);
        let first = maki_privileged::exec::execute(&plan);
        assert_eq!(libc::setrlimit(libc::RLIMIT_FSIZE, &original), 0);
        libc::signal(libc::SIGXFSZ, old_signal);
        assert!(first.is_err());
    }
    let root = std::path::Path::new(&path);
    assert!(
        !root.join(SENTINEL_FILE).exists(),
        "partial final sentinel was published"
    );
    assert_eq!(
        std::fs::read_dir(root).unwrap().count(),
        0,
        "failed attempt left temp files"
    );
    maki_privileged::exec::execute(&plan).unwrap();
    assert_eq!(
        std::fs::read(root.join(SENTINEL_FILE)).unwrap(),
        format!("{uuid}\n").as_bytes()
    );
    maki_privileged::exec::execute(&plan).unwrap();
}

#[test]
fn failed_partial_write_can_retry_without_operator_repair() {
    let root = std::env::temp_dir().join(format!(
        "maki-sentinel-partial-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir(&root).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "partial_sentinel_child", "--nocapture"])
        .env("MAKI_SENTINEL_PARTIAL_CHILD", &root)
        .output()
        .unwrap();
    let _ = std::fs::remove_dir_all(&root);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
}
