//! Interrupt a test's child process at one system call.
//!
//! A seccomp filter installed on the calling thread acts on each matching
//! call of that thread and of the threads it starts afterwards: it kills
//! the process (a crash at that call) or makes the call fail with an errno
//! (a full disk at that call) while the process goes on.

/// The filter action that makes the call fail with `errno`.
pub fn fails_with(errno: i32) -> u32 {
    libc::SECCOMP_RET_ERRNO | (errno as u32 & libc::SECCOMP_RET_DATA)
}

/// The filter action that kills the process at the call.
pub const KILLS: u32 = libc::SECCOMP_RET_KILL_PROCESS;

/// Apply `action` to every `call` whose third argument (a write's length,
/// for `pwrite64`) is `third`, or to every `call` when `third` is `None`.
/// False where seccomp filters are unavailable.
pub fn on(call: libc::c_long, third: Option<u32>, action: u32) -> bool {
    let statement = |code: u32, k: u32, jt: u8, jf: u8| libc::sock_filter {
        code: code as u16,
        jt,
        jf,
        k,
    };
    let load = |offset: u32| statement(libc::BPF_LD | libc::BPF_W | libc::BPF_ABS, offset, 0, 0);
    let equal = |k: u32, jf: u8| statement(libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K, k, 0, jf);
    let ret = |k: u32| statement(libc::BPF_RET | libc::BPF_K, k, 0, 0);
    // seccomp_data: nr at 0, args from 16; the low half of args[2] at 32.
    let filter = match third {
        Some(third) => vec![
            load(0),
            equal(call as u32, 3),
            load(32),
            equal(third, 1),
            ret(action),
            ret(libc::SECCOMP_RET_ALLOW),
        ],
        None => vec![
            load(0),
            equal(call as u32, 1),
            ret(action),
            ret(libc::SECCOMP_RET_ALLOW),
        ],
    };
    let program = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };
    // SAFETY: both calls affect only this thread and the threads it starts
    // later; the program outlives them.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0
            && libc::prctl(
                libc::PR_SET_SECCOMP,
                libc::SECCOMP_MODE_FILTER,
                &program as *const libc::sock_fprog,
            ) == 0
    }
}
