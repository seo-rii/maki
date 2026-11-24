//! The connect's answer to a busy device, against a scripted kernel and a
//! manual clock: the kernel refuses `NBD_CMD_CONNECT` with `EBUSY` while
//! anything holds the unconnected device open (udev's probe right after a
//! disconnect), so a connect retries for a bounded time; every other answer
//! is final. Also the family check and the sysfs connection check.

use super::netlink::{
    Family, Unacknowledged, COMMAND_SEQUENCE, NBD_ATTR_BACKEND_IDENTIFIER, NBD_ATTR_INDEX,
    NBD_CMD_CONNECT,
};
use super::*;

use std::collections::VecDeque;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

const INDEX: u32 = 3;

type Answer = Result<Vec<Vec<u8>>, Unacknowledged>;

/// A kernel that answers each connect from a script (then `EBUSY` for
/// ever), and may show a connection from some check on.
struct Kernel {
    answers: VecDeque<Answer>,
    /// The `shows_connection` call (counted from 1) from which the device
    /// shows a connection.
    connected_from_check: Option<usize>,
    clock: Instant,
    started: Instant,
    seqs: Vec<u32>,
    checks: usize,
    slept: Duration,
}

impl Kernel {
    fn new(answers: Vec<Answer>) -> Self {
        let started = Instant::now();
        Self {
            answers: answers.into(),
            connected_from_check: None,
            clock: started,
            started,
            seqs: Vec::new(),
            checks: 0,
            slept: Duration::ZERO,
        }
    }

    fn elapsed(&self) -> Duration {
        self.clock - self.started
    }
}

impl Attempts for Kernel {
    fn connect(&mut self, seq: u32) -> Result<Answer, NbdError> {
        self.seqs.push(seq);
        Ok(self
            .answers
            .pop_front()
            .unwrap_or(Err(Unacknowledged::Refused(libc::EBUSY))))
    }

    fn shows_connection(&mut self) -> Result<bool, NbdError> {
        self.checks += 1;
        Ok(self
            .connected_from_check
            .is_some_and(|from| self.checks >= from))
    }

    fn now(&self) -> Instant {
        self.clock
    }

    fn sleep(&mut self, duration: Duration) {
        self.clock += duration;
        self.slept += duration;
    }
}

fn busy() -> Answer {
    Err(Unacknowledged::Refused(libc::EBUSY))
}

#[test]
fn a_busy_device_is_retried_until_the_kernel_connects_it() {
    let mut kernel = Kernel::new(vec![busy(), busy(), Ok(Vec::new())]);
    let deadline = kernel.now() + Duration::from_secs(120);
    connect_retrying(INDEX, deadline, &mut kernel).unwrap();
    // Each attempt is a request of its own, after a check that the device
    // still shows no connection.
    assert_eq!(
        kernel.seqs,
        [COMMAND_SEQUENCE, COMMAND_SEQUENCE + 1, COMMAND_SEQUENCE + 2]
    );
    assert_eq!(kernel.checks, 2);
    assert_eq!(kernel.slept, BUSY_RETRY_INTERVAL * 2);
}

#[test]
fn a_device_busy_for_the_whole_window_is_refused_as_busy() {
    let mut kernel = Kernel::new(Vec::new());
    let deadline = kernel.now() + Duration::from_secs(120);
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::Failed(message)) => {
            assert!(message.contains("Device or resource busy"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert!(
        kernel.elapsed() <= BUSY_RETRY_WINDOW,
        "{:?}",
        kernel.elapsed()
    );
    assert!(
        kernel.elapsed() + BUSY_RETRY_INTERVAL * 2 >= BUSY_RETRY_WINDOW,
        "gave up after {:?}",
        kernel.elapsed()
    );
    assert_eq!(kernel.seqs.len(), kernel.checks + 1);
}

#[test]
fn the_retries_end_at_the_steps_deadline() {
    let mut kernel = Kernel::new(Vec::new());
    // A finish_by deadline (the failed-start hook's) shorter than the window.
    let deadline = kernel.now() + Duration::from_millis(350);
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::Failed(message)) => {
            assert!(message.contains("Device or resource busy"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert!(kernel.now() <= deadline, "{:?}", kernel.elapsed());
    assert!(kernel.seqs.len() <= 4, "{} attempts", kernel.seqs.len());
}

#[test]
fn a_device_that_shows_a_connection_is_not_retried() {
    let mut kernel = Kernel::new(vec![busy()]);
    kernel.connected_from_check = Some(1);
    let deadline = kernel.now() + Duration::from_secs(120);
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::Failed(message)) => {
            assert!(message.contains("shows a connection"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(kernel.seqs.len(), 1, "no request after the check");
}

#[test]
fn every_other_answer_is_final() {
    for (answer, unknown) in [
        (Err(Unacknowledged::Refused(libc::EINVAL)), false),
        (Err(Unacknowledged::Refused(libc::EPERM)), false),
        (
            Err(Unacknowledged::Unanswered(io::Error::new(
                io::ErrorKind::TimedOut,
                "no answer",
            ))),
            true,
        ),
    ] {
        let mut kernel = Kernel::new(vec![answer]);
        let deadline = kernel.now() + Duration::from_secs(120);
        let result = connect_retrying(INDEX, deadline, &mut kernel);
        match (&result, unknown) {
            (Err(NbdError::Failed(_)), false) | (Err(NbdError::Unknown(_)), true) => {}
            _ => panic!("{result:?}"),
        }
        assert_eq!((kernel.seqs.len(), kernel.checks), (1, 0), "{result:?}");
        assert_eq!(kernel.slept, Duration::ZERO);
    }
    // A reply that names another device is no connect of this one.
    let reply = {
        let mut payload = vec![NBD_CMD_CONNECT, 1, 0, 0];
        payload.extend_from_slice(&8u16.to_ne_bytes());
        payload.extend_from_slice(&NBD_ATTR_INDEX.to_ne_bytes());
        payload.extend_from_slice(&(INDEX + 1).to_ne_bytes());
        payload
    };
    let mut kernel = Kernel::new(vec![Ok(vec![reply])]);
    let deadline = kernel.now() + Duration::from_secs(120);
    assert!(matches!(
        connect_retrying(INDEX, deadline, &mut kernel),
        Err(NbdError::Unknown(_))
    ));
}

#[test]
fn a_family_without_the_backend_identifier_is_refused() {
    for max_attr in [0, u32::from(NBD_ATTR_BACKEND_IDENTIFIER) - 1] {
        match check_family(&Family { id: 0x1e, max_attr }) {
            Err(NbdError::Failed(message)) => {
                assert!(message.contains("backend identifier"), "{message}")
            }
            other => panic!("{max_attr}: {other:?}"),
        }
    }
    for max_attr in [u32::from(NBD_ATTR_BACKEND_IDENTIFIER), 11, u32::MAX] {
        check_family(&Family { id: 0x1e, max_attr }).unwrap();
    }
}

static TREES: AtomicU64 = AtomicU64::new(0);

#[test]
fn a_device_shows_a_connection_by_its_pid_or_backend() {
    let sysfs: PathBuf = std::env::temp_dir().join(format!(
        "maki-nbd-sysfs-{}-{}",
        std::process::id(),
        TREES.fetch_add(1, Ordering::Relaxed)
    ));
    for (index, pid, backend) in [
        (0, false, None),
        (1, true, None),
        (2, false, Some("maki-x")),
        (3, false, Some("")),
        (4, true, Some("maki-x")),
    ] {
        let directory = sysfs.join(format!("nbd{index}"));
        std::fs::create_dir_all(&directory).unwrap();
        if pid {
            std::fs::write(directory.join("pid"), "4242\n").unwrap();
        }
        if let Some(backend) = backend {
            std::fs::write(directory.join("backend"), format!("{backend}\n")).unwrap();
        }
    }
    let shows = |index| device_shows_connection(&sysfs, index).unwrap();
    assert_eq!(
        [shows(0), shows(1), shows(2), shows(3), shows(4), shows(9)],
        [false, true, true, false, true, false]
    );
    let _ = std::fs::remove_dir_all(&sysfs);
}
