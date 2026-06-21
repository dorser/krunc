//! `forktest` — a deterministic probe for the cgroup `pids` controller.
//!
//! It calls [`fork(2)`](https://man7.org/linux/man-pages/man2/fork.2.html) in a
//! loop until the kernel refuses (typically `EAGAIN`, once the enclosing
//! cgroup's `pids.max` is reached), reports how many children it started, then
//! keeps every process alive (each one `pause(2)`s) so the host can observe
//! `pids.current == pids.max` from outside the container. The host then stops
//! the whole tree with `krunc kill`.
//!
//! Why a dedicated binary rather than a shell `&` loop: a non-interactive shell
//! redirects each background job's stdin from `/dev/null`, which a hardened
//! krunc container intentionally does not have, so `cmd &` fails before the
//! cgroup limit is ever exercised. Calling `fork(2)` directly needs no `/dev`
//! and is immune to job-control quirks, making the enforcement test robust and
//! reproducible.

use std::io::Write;

/// Upper bound on fork attempts. Chosen far above any `pids.max` we test with so
/// the cgroup limit — not this constant — is what stops us.
const MAX_ATTEMPTS: usize = 1024;

fn errno() -> i32 {
    // SAFETY: `__errno_location` returns a valid pointer to this thread's errno.
    unsafe { *libc::__errno_location() }
}

/// Block forever, counting as one live pid, until the host delivers a signal.
fn park() -> ! {
    loop {
        // SAFETY: `pause` takes no arguments and only returns when a signal is
        // delivered; looping keeps the process resident until it is killed.
        unsafe { libc::pause() };
    }
}

fn main() {
    let mut started = 0usize;
    let mut denied = 0usize;
    let mut last_errno = 0i32;

    for _ in 0..MAX_ATTEMPTS {
        // SAFETY: `fork` takes no arguments. This process is single-threaded and
        // the child only calls async-signal-safe libc functions (`pause`) and
        // never returns into Rust, so no inherited runtime state is touched.
        match unsafe { libc::fork() } {
            -1 => {
                denied += 1;
                last_errno = errno();
                // A couple of extra attempts confirm the limit is sticky (each
                // bumps the cgroup's pids.events `max` counter the host reads).
                if denied >= 3 {
                    break;
                }
            }
            0 => park(), // child: hold so it is charged to the cgroup
            _ => started += 1,
        }
    }

    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "[forktest] started {started} children, fork denied {denied}x (errno={last_errno})"
    );
    let _ = err.flush();

    // The parent stays alive (one more pid) so the survivors persist for the
    // host's `pids.current` snapshot; the host stops us with `krunc kill`.
    park();
}
