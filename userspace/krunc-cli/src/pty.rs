//! Minimal pseudo-terminal support for `krunc run -t`.
//!
//! krunc needs no kernel changes for an interactive terminal: the container init
//! is cloned from the task that issues the `create` ioctl and inherits a copy of
//! its file descriptors (that is already why a container's stdout reaches the
//! caller). So for `-t` we `openpty(3)`, `fork(2)`, and in the child wire the
//! pty *slave* to stdio before running the container lifecycle — the container
//! then inherits the slave as its controlling terminal — while the parent relays
//! bytes between the user's terminal and the pty *master*.

use std::os::fd::RawFd;

pub struct Pty {
    pub master: RawFd,
    pub slave: RawFd,
}

/// Allocate a pseudo-terminal pair. musl ships `openpty` in libc, so this links
/// into the static binary with no extra libs. Requires a `devpts` mount.
pub fn open() -> Result<Pty, String> {
    let mut master: RawFd = -1;
    let mut slave: RawFd = -1;
    // SAFETY: master/slave are valid out-params; the termios/winsize/name args
    // are NULL (kernel defaults, no name returned).
    let rc = unsafe {
        libc::openpty(
            &mut master,
            &mut slave,
            std::ptr::null_mut(),
            std::ptr::null(),
            std::ptr::null(),
        )
    };
    if rc != 0 {
        return Err(format!("openpty: {}", std::io::Error::last_os_error()));
    }
    Ok(Pty { master, slave })
}

/// Put terminal `fd` into raw mode, returning the previous settings to restore on
/// exit. Returns `None` if `fd` is not a terminal (e.g. stdin is a pipe), in
/// which case there is nothing to restore.
pub fn set_raw(fd: RawFd) -> Option<libc::termios> {
    // SAFETY: `t` is a valid out-param for tcgetattr; only used if it succeeds.
    unsafe {
        let mut t: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut t) != 0 {
            return None;
        }
        let saved = t;
        libc::cfmakeraw(&mut t);
        libc::tcsetattr(fd, libc::TCSANOW, &t);
        Some(saved)
    }
}

/// Restore terminal `fd` to previously-saved settings (no-op if `None`).
pub fn restore(fd: RawFd, saved: Option<libc::termios>) {
    if let Some(t) = saved {
        // SAFETY: `t` was produced by tcgetattr on this fd.
        unsafe {
            libc::tcsetattr(fd, libc::TCSANOW, &t);
        }
    }
}

/// In the forked child (the container side): start a new session, make the pty
/// slave the controlling terminal, and wire it to stdin/stdout/stderr. The
/// container init, cloned from here, inherits this terminal.
pub fn wire_slave(p: &Pty) {
    // SAFETY: standard controlling-terminal setup on a freshly-forked child that
    // has not yet run any container code; all fds are valid.
    unsafe {
        libc::setsid();
        libc::ioctl(p.slave, libc::TIOCSCTTY as _, 0);
        for dst in 0..3 {
            libc::dup2(p.slave, dst);
        }
        if p.master > 2 {
            libc::close(p.master);
        }
        if p.slave > 2 {
            libc::close(p.slave);
        }
    }
}

/// In the parent: relay bytes between our stdin/stdout and the pty `master`
/// until the master reports EOF (all slaves closed — the container exited).
pub fn relay(master: RawFd) {
    let mut fds = [
        libc::pollfd { fd: master, events: libc::POLLIN, revents: 0 },
        libc::pollfd { fd: 0, events: libc::POLLIN, revents: 0 },
    ];
    let mut buf = [0u8; 4096];
    loop {
        // SAFETY: fds is a valid array of 2 pollfds.
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, -1) };
        if n < 0 {
            if std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break;
        }
        // container output (master) -> our stdout
        if fds[0].revents & (libc::POLLIN | libc::POLLHUP | libc::POLLERR) != 0 {
            // SAFETY: buf is valid for buf.len() bytes.
            let r = unsafe { libc::read(master, buf.as_mut_ptr().cast(), buf.len()) };
            if r <= 0 {
                break; // EOF/error: the container's terminal closed
            }
            write_all(1, &buf[..r as usize]);
        }
        // user input (our stdin) -> container (master)
        if fds[1].fd >= 0 && fds[1].revents & libc::POLLIN != 0 {
            // SAFETY: buf is valid for buf.len() bytes.
            let r = unsafe { libc::read(0, buf.as_mut_ptr().cast(), buf.len()) };
            if r > 0 {
                write_all(master, &buf[..r as usize]);
            } else {
                fds[1].fd = -1; // stdin EOF: stop forwarding input, keep relaying output
            }
        }
    }
}

fn write_all(fd: RawFd, mut data: &[u8]) {
    while !data.is_empty() {
        // SAFETY: data points to data.len() valid bytes.
        let w = unsafe { libc::write(fd, data.as_ptr().cast(), data.len()) };
        if w <= 0 {
            break;
        }
        data = &data[w as usize..];
    }
}
