//! The connect's answer to "busy", against a scripted daemon and kernel and
//! a manual clock. The kernel refuses `NBD_CMD_CONNECT` with `EBUSY` while
//! anything holds the unconnected device open (udev's probe right after a
//! disconnect), before it takes the socket; the daemon answers that its
//! export is not available until it has closed its previous connection.
//! Both are retried for a bounded time from the first of them, the kernel's
//! on the connection already negotiated; every other answer is final. Also
//! the family check and the sysfs connection check.

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

/// How one negotiation with the scripted daemon ends.
#[derive(Clone, Copy)]
enum Handshake {
    Ready,
    /// `NBD_REP_ERR_UNKNOWN`: the export is not available.
    Unavailable,
    /// Any other failure: a wrong server, a closed socket.
    Fails,
}

/// A daemon and a kernel that answer from scripts, and a device that may
/// show a connection from some check on.
struct Kernel {
    /// The kernel's answers to each request, then `EBUSY` for ever.
    answers: VecDeque<Answer>,
    /// How each negotiation ends, then `after_handshakes` for ever.
    handshakes: VecDeque<Handshake>,
    after_handshakes: Handshake,
    /// How long the daemon takes over each negotiation.
    handshake_takes: Duration,
    /// Whether a busy answer leaves the negotiated connection usable: it
    /// does when the kernel refused before it took the socket.
    busy_keeps_the_connection: bool,
    /// The `shows_connection` call (counted from 1) from which the device
    /// shows a connection.
    connected_from_check: Option<usize>,
    clock: Instant,
    started: Instant,
    /// A negotiated connection the helper can hand to the kernel.
    open: bool,
    negotiations: usize,
    seqs: Vec<u32>,
    checks: usize,
    slept: Duration,
}

impl Kernel {
    fn new(answers: Vec<Answer>) -> Self {
        let started = Instant::now();
        Self {
            answers: answers.into(),
            handshakes: VecDeque::new(),
            after_handshakes: Handshake::Ready,
            handshake_takes: Duration::ZERO,
            busy_keeps_the_connection: true,
            connected_from_check: None,
            clock: started,
            started,
            open: false,
            negotiations: 0,
            seqs: Vec::new(),
            checks: 0,
            slept: Duration::ZERO,
        }
    }

    fn elapsed(&self) -> Duration {
        self.clock - self.started
    }

    fn deadline(&self) -> Instant {
        self.started + Duration::from_secs(120)
    }
}

impl Attempts for Kernel {
    fn negotiate(&mut self) -> Result<Negotiation, NbdError> {
        self.negotiations += 1;
        self.clock += self.handshake_takes;
        self.open = false;
        match self.handshakes.pop_front().unwrap_or(self.after_handshakes) {
            Handshake::Ready => {
                self.open = true;
                Ok(Negotiation::Ready)
            }
            Handshake::Unavailable => Ok(Negotiation::ExportUnavailable(
                "the NBD handshake on /run/maki/pg/nbd.sock failed: the server refused \
                 NBD_OPT_GO with NBD_REP_ERR_UNKNOWN"
                    .into(),
            )),
            Handshake::Fails => Err(NbdError::Failed(
                "the NBD handshake on /run/maki/pg/nbd.sock failed: the server closed the \
                 connection during the NBD handshake"
                    .into(),
            )),
        }
    }

    fn reusable(&mut self) -> bool {
        self.open
    }

    fn request(&mut self, seq: u32) -> Answer {
        assert!(self.open, "a request without a usable connection");
        self.seqs.push(seq);
        let answer = self
            .answers
            .pop_front()
            .unwrap_or(Err(Unacknowledged::Refused(libc::EBUSY)));
        self.open = matches!(answer, Err(Unacknowledged::Refused(libc::EBUSY)))
            && self.busy_keeps_the_connection;
        answer
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
    let deadline = kernel.deadline();
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

/// The kernel answers `EBUSY` before it takes the socket: the next request
/// goes out on the same negotiated connection. A fresh one would ask the
/// daemon, which serves one connection at a time, for a second.
#[test]
fn a_busy_device_is_retried_on_the_negotiated_connection() {
    let mut kernel = Kernel::new(vec![busy(), busy(), Ok(Vec::new())]);
    let deadline = kernel.deadline();
    connect_retrying(INDEX, deadline, &mut kernel).unwrap();
    assert_eq!(kernel.negotiations, 1, "negotiations with the daemon");
    assert_eq!(kernel.seqs.len(), 3);
}

/// A refusal after the kernel took the socket shuts it down: such a
/// connection is not handed to the kernel again.
#[test]
fn a_connection_that_is_no_longer_usable_is_negotiated_again() {
    let mut kernel = Kernel::new(vec![busy(), busy(), Ok(Vec::new())]);
    kernel.busy_keeps_the_connection = false;
    let deadline = kernel.deadline();
    connect_retrying(INDEX, deadline, &mut kernel).unwrap();
    assert_eq!(kernel.negotiations, 3);
    assert_eq!(kernel.seqs.len(), 3);
}

/// The daemon serves one connection and closes one a moment after its peer
/// did: a handshake that arrives before that is answered "not available",
/// and is tried again like a busy device.
#[test]
fn an_unavailable_export_is_retried_until_the_daemon_serves_it() {
    let mut kernel = Kernel::new(vec![Ok(Vec::new())]);
    kernel.handshakes = [Handshake::Unavailable, Handshake::Unavailable].into();
    let deadline = kernel.deadline();
    connect_retrying(INDEX, deadline, &mut kernel).unwrap();
    assert_eq!(kernel.negotiations, 3);
    assert_eq!(kernel.seqs, [COMMAND_SEQUENCE], "one request, once ready");
    assert_eq!(kernel.checks, 2);
    assert_eq!(kernel.slept, BUSY_RETRY_INTERVAL * 2);
}

/// Inside the busy window too: the kernel shut the connection down, and the
/// daemon has not closed its end when the next handshake arrives.
#[test]
fn an_unavailable_export_after_a_busy_device_is_retried() {
    let mut kernel = Kernel::new(vec![busy(), Ok(Vec::new())]);
    kernel.busy_keeps_the_connection = false;
    kernel.handshakes = [Handshake::Ready, Handshake::Unavailable].into();
    let deadline = kernel.deadline();
    connect_retrying(INDEX, deadline, &mut kernel).unwrap();
    assert_eq!(kernel.negotiations, 3);
    assert_eq!(kernel.seqs.len(), 2);
}

/// A server without a default export answers the same as a busy one, so the
/// wait is bounded, and the refusal names both.
#[test]
fn an_export_that_stays_unavailable_is_refused_when_the_window_ends() {
    let mut kernel = Kernel::new(Vec::new());
    kernel.after_handshakes = Handshake::Unavailable;
    let deadline = kernel.deadline();
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::Failed(message)) => {
            for expected in [
                "NBD_REP_ERR_UNKNOWN",
                "busy with another connection",
                "no default export",
            ] {
                assert!(message.contains(expected), "{message}");
            }
        }
        other => panic!("{other:?}"),
    }
    assert!(kernel.seqs.is_empty(), "the kernel was asked");
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
}

/// The window is for the busy answers. A first handshake the daemon was
/// slow to answer takes nothing from it.
#[test]
fn the_busy_window_starts_at_the_first_busy_answer() {
    let mut kernel = Kernel::new(vec![busy(), Ok(Vec::new())]);
    kernel.handshake_takes = BUSY_RETRY_WINDOW - Duration::from_millis(50);
    let deadline = kernel.deadline();
    connect_retrying(INDEX, deadline, &mut kernel).unwrap();
    assert_eq!(kernel.seqs.len(), 2, "the busy device was retried");
}

/// A device busy to the end is told apart from every other refusal:
/// nothing changed, and an attach that chose the device may take another.
#[test]
fn a_device_busy_for_the_whole_window_is_refused_as_busy() {
    let mut kernel = Kernel::new(Vec::new());
    let deadline = kernel.deadline();
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::DeviceBusy(message)) => {
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
    assert_eq!(kernel.negotiations, 1);
}

#[test]
fn the_retries_end_at_the_steps_deadline() {
    for unavailable in [false, true] {
        let mut kernel = Kernel::new(Vec::new());
        if unavailable {
            kernel.after_handshakes = Handshake::Unavailable;
        }
        // A finish_by deadline (the failed-start hook's) shorter than the
        // window.
        let deadline = kernel.now() + Duration::from_millis(350);
        match connect_retrying(INDEX, deadline, &mut kernel) {
            Err(NbdError::DeviceBusy(message)) if !unavailable => {
                assert!(message.contains("Device or resource busy"), "{message}")
            }
            Err(NbdError::Failed(message)) if unavailable => {
                assert!(message.contains("NBD_REP_ERR_UNKNOWN"), "{message}")
            }
            other => panic!("{other:?}"),
        }
        assert!(kernel.now() <= deadline, "{:?}", kernel.elapsed());
        assert!(
            kernel.seqs.len() + kernel.negotiations <= 5,
            "{} requests, {} negotiations",
            kernel.seqs.len(),
            kernel.negotiations
        );
    }
}

#[test]
fn a_device_that_shows_a_connection_is_not_retried() {
    let mut kernel = Kernel::new(vec![busy()]);
    kernel.connected_from_check = Some(1);
    let deadline = kernel.deadline();
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::Failed(message)) => {
            assert!(
                message.contains("busy and now shows a connection"),
                "{message}"
            )
        }
        other => panic!("{other:?}"),
    }
    assert_eq!(kernel.seqs.len(), 1, "no request after the check");

    // Nor after a wait for the daemon's export.
    let mut kernel = Kernel::new(Vec::new());
    kernel.handshakes = [Handshake::Unavailable].into();
    kernel.connected_from_check = Some(1);
    let deadline = kernel.deadline();
    match connect_retrying(INDEX, deadline, &mut kernel) {
        Err(NbdError::Failed(message)) => {
            assert!(message.contains("shows a connection"), "{message}")
        }
        other => panic!("{other:?}"),
    }
    assert_eq!((kernel.negotiations, kernel.seqs.len()), (1, 0));
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
        let deadline = kernel.deadline();
        let result = connect_retrying(INDEX, deadline, &mut kernel);
        match (&result, unknown) {
            (Err(NbdError::Failed(_)), false) | (Err(NbdError::Unknown(_)), true) => {}
            _ => panic!("{result:?}"),
        }
        assert_eq!((kernel.seqs.len(), kernel.checks), (1, 0), "{result:?}");
        assert_eq!(kernel.slept, Duration::ZERO);
    }
    // A handshake that fails in any other way than "not available": a
    // wrong server, a daemon that went away. At once, and also after a busy
    // answer.
    for answers in [Vec::new(), vec![busy()]] {
        let after_busy = !answers.is_empty();
        let mut kernel = Kernel::new(answers);
        kernel.busy_keeps_the_connection = false;
        kernel.handshakes = if after_busy {
            [Handshake::Ready, Handshake::Fails].into()
        } else {
            [Handshake::Fails].into()
        };
        let deadline = kernel.deadline();
        let result = connect_retrying(INDEX, deadline, &mut kernel);
        assert!(matches!(result, Err(NbdError::Failed(_))), "{result:?}");
        assert_eq!(kernel.negotiations, 1 + usize::from(after_busy));
        assert_eq!(kernel.seqs.len(), usize::from(after_busy));
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
    let deadline = kernel.deadline();
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
