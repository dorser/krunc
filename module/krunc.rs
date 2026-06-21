// SPDX-License-Identifier: GPL-2.0
//! # krunc — a container runtime in the kernel
//!
//! `krunc` ("kernel runc") is a proof-of-concept OCI-ish container runtime
//! implemented as a Rust kernel module. Unlike `runc`, which is a userspace
//! program that issues `clone`/`unshare`/`mount`/`pivot_root`/`execve`
//! syscalls, krunc performs the entire container *orchestration* — namespace
//! creation, rootfs entry and process exec — inside the kernel.
//!
//! ## Interface
//!
//! krunc registers a misc character device `/dev/krunc`. It is intentionally
//! "hardened"/narrow: the only way to talk to it is a single-line text command,
//! which makes it trivially scriptable from a minimal (busybox) userland:
//!
//! ```text
//! # start a container
//! echo 'run rootfs=/containers/demo host=demo exec=/bin/sh arg=/init.sh' > /dev/krunc
//! # list containers
//! cat /dev/krunc
//! # stop a container (by host-visible pid)
//! echo 'kill 1234' > /dev/krunc
//! ```
//!
//! ## How a container is created (all in kernel context)
//!
//! 1. `write()` runs in the context of the calling process; krunc parses the
//!    spec and calls [`user_mode_thread`] with the namespace clone flags
//!    (`CLONE_NEWPID|NEWNS|NEWUTS|NEWIPC|NEWNET`). This creates a task that is
//!    PID 1 inside a brand-new set of namespaces and is allowed to later
//!    `execve()` into userspace (the same primitive the kernel uses to create
//!    the real init at boot).
//! 2. That task runs [`container_entry`] in kernel context, which:
//!      * sets the container hostname in its private UTS namespace,
//!      * performs an in-kernel chroot into the container rootfs,
//!      * `kernel_execve()`s the requested binary, becoming the container's
//!        userspace PID 1.
//!
//! The handful of kernel primitives that mainline does not export to modules
//! (`user_mode_thread`, `kernel_execve`) plus two thin struct/locking helpers
//! (`krunc_chroot`, `krunc_set_hostname`, `krunc_kill`) are provided by a small
//! `kernel/krunc_exports.c` shim compiled into vmlinux. All policy and logic
//! lives here, in Rust.

use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use kernel::{
    c_str,
    error::Error,
    ffi::{c_char, c_int, c_ulong, c_void},
    fs::{File, Kiocb},
    iov::{IovIterDest, IovIterSource},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    prelude::*,
    str::CString,
    types::ForeignOwnable,
};

module! {
    type: KruncModule,
    name: "krunc",
    authors: ["krunc"],
    description: "A container runtime implemented in the kernel (PoC)",
    license: "GPL",
}

// -- FFI: primitives exported by kernel/krunc_exports.c (built into vmlinux) ---
extern "C" {
    /// Create a task in fresh namespaces that can later `kernel_execve()`.
    /// Returns the new task's pid in the caller's pid namespace, or -errno.
    fn user_mode_thread(
        f: unsafe extern "C" fn(*mut c_void) -> c_int,
        arg: *mut c_void,
        flags: c_ulong,
    ) -> c_int;
    /// Exec a binary from kernel context (becomes userspace on success).
    fn kernel_execve(
        filename: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    /// Set the nodename of the *current* task's UTS namespace.
    fn krunc_set_hostname(name: *const c_char, len: usize) -> c_int;
    /// In-kernel chroot of the *current* task into `path`.
    fn krunc_chroot(path: *const c_char) -> c_int;
    /// Send `sig` to the task with host-visible pid `nr`.
    fn krunc_kill(nr: c_int, sig: c_int) -> c_int;
}

// clone(2) namespace flags (uapi/linux/sched.h)
const CLONE_NEWNS: c_ulong = 0x0002_0000;
const CLONE_NEWUTS: c_ulong = 0x0400_0000;
const CLONE_NEWIPC: c_ulong = 0x0800_0000;
const CLONE_NEWPID: c_ulong = 0x2000_0000;
const CLONE_NEWNET: c_ulong = 0x4000_0000;
const SIGCHLD: c_ulong = 17;
const SIGKILL: c_int = 9;

/// All namespaces krunc isolates by default, plus SIGCHLD so the container is a
/// reapable child of the caller.
const KRUNC_CLONE_FLAGS: c_ulong =
    CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD;

/// Maximum argv entries handed to the container (argv[0] is the binary).
const MAX_ARGS: usize = 8;
/// Maximum bytes per argv entry (copied onto the kernel stack before exec).
const ARG_LEN: usize = 256;
/// Maximum accepted spec line length.
const MAX_SPEC: usize = 4096;

/// Heap context handed to the new task. Owned by [`container_entry`], which
/// frees it before `execve` (so there is no per-container leak).
struct ContainerCtx {
    /// NUL-terminated hostname.
    hostname: KVec<u8>,
    /// NUL-terminated host path of the container rootfs.
    rootfs: KVec<u8>,
    /// argv; argv[0] is the binary. Each entry is NUL-terminated.
    argv: KVec<KVec<u8>>,
}

/// A launched container, for status/listing.
struct Container {
    id: u64,
    pid: i32,
    hostname: KVec<u8>,
}

kernel::sync::global_lock! {
    /// Registry of launched containers.
    ///
    /// # Safety
    /// Initialized exactly once in [`KruncModule::init`] before any use.
    unsafe(uninit) static REGISTRY: Mutex<KVec<Container>> = KVec::new();
}

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

#[pin_data]
struct KruncModule {
    #[pin]
    _miscdev: MiscDeviceRegistration<KruncDevice>,
}

impl kernel::InPlaceModule for KruncModule {
    fn init(_module: &'static ThisModule) -> impl PinInit<Self, Error> {
        // SAFETY: module init runs exactly once before any other access.
        unsafe { REGISTRY.init() };
        pr_info!("loading kernel container runtime; control device /dev/krunc\n");

        let options = MiscDeviceOptions {
            name: c_str!("krunc"),
        };
        try_pin_init!(Self {
            _miscdev <- MiscDeviceRegistration::register(options),
        })
    }
}

/// Per-open state. krunc keeps all real state in the global [`REGISTRY`], so
/// this is just a marker.
struct KruncDevice;

#[vtable]
impl MiscDevice for KruncDevice {
    type Ptr = KBox<KruncDevice>;

    fn open(_file: &File, _misc: &MiscDeviceRegistration<Self>) -> Result<KBox<KruncDevice>> {
        Ok(KBox::new(KruncDevice, GFP_KERNEL)?)
    }

    /// A write is a single command line: `run ...` or `kill <pid>`.
    fn write_iter(_kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterSource<'_>) -> Result<usize> {
        let mut buf: KVec<u8> = KVec::new();
        let len = iov.copy_from_iter_vec(&mut buf, GFP_KERNEL)?;
        if buf.len() > MAX_SPEC {
            return Err(EINVAL);
        }
        handle_command(&buf)?;
        Ok(len)
    }

    /// A read returns the container table.
    fn read_iter(mut kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let out = render_status()?;
        let read = iov.simple_read_from_buffer(kiocb.ki_pos_mut(), &out)?;
        Ok(read)
    }
}

// ----------------------------- command handling ------------------------------

fn is_ws(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'\n')
}

fn trim(mut s: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = s {
        if is_ws(*first) {
            s = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = s {
        if is_ws(*last) {
            s = rest;
        } else {
            break;
        }
    }
    s
}

fn parse_i32(s: &[u8]) -> Option<i32> {
    let s = trim(s);
    if s.is_empty() {
        return None;
    }
    let (neg, digits) = match s {
        [b'-', rest @ ..] => (true, rest),
        [b'+', rest @ ..] => (false, rest),
        _ => (false, s),
    };
    if digits.is_empty() {
        return None;
    }
    let mut v: i64 = 0;
    for &b in digits {
        if !b.is_ascii_digit() {
            return None;
        }
        v = v.checked_mul(10)?.checked_add((b - b'0') as i64)?;
        if v > i32::MAX as i64 + 1 {
            return None;
        }
    }
    if neg {
        v = -v;
    }
    if v < i32::MIN as i64 || v > i32::MAX as i64 {
        return None;
    }
    Some(v as i32)
}

/// Build a NUL-terminated kernel byte vector from `s`.
fn to_cvec(s: &[u8]) -> Result<KVec<u8>> {
    let mut v = KVec::with_capacity(s.len() + 1, GFP_KERNEL)?;
    v.extend_from_slice(s, GFP_KERNEL)?;
    v.push(0, GFP_KERNEL)?;
    Ok(v)
}

fn handle_command(buf: &[u8]) -> Result {
    let line = trim(buf);
    if line.is_empty() {
        return Err(EINVAL);
    }

    // `kill <pid>` / `kill=<pid>`
    if let Some(rest) = line.strip_prefix(b"kill") {
        let rest = rest.strip_prefix(b"=").unwrap_or(rest);
        let pid = parse_i32(rest).ok_or(EINVAL)?;
        // SAFETY: simple FFI call into the vmlinux helper.
        let rc = unsafe { krunc_kill(pid, SIGKILL) };
        if rc < 0 {
            pr_warn!("kill {} failed: {}\n", pid, rc);
            return Err(Error::from_errno(rc));
        }
        REGISTRY.lock().retain(|c| c.pid != pid);
        pr_info!("killed container pid {}\n", pid);
        return Ok(());
    }

    run_container(line)
}

fn run_container(line: &[u8]) -> Result {
    let mut rootfs: Option<KVec<u8>> = None;
    let mut host: Option<KVec<u8>> = None;
    let mut exec: Option<KVec<u8>> = None;
    let mut args: KVec<KVec<u8>> = KVec::new();

    let mut i = 0;
    while i < line.len() {
        while i < line.len() && is_ws(line[i]) {
            i += 1;
        }
        let start = i;
        while i < line.len() && !is_ws(line[i]) {
            i += 1;
        }
        if start == i {
            break;
        }
        let tok = &line[start..i];
        let (key, val) = match tok.iter().position(|&b| b == b'=') {
            Some(p) => (&tok[..p], &tok[p + 1..]),
            None => (tok, &tok[tok.len()..]),
        };
        match key {
            b"rootfs" => rootfs = Some(to_cvec(val)?),
            b"host" | b"hostname" => host = Some(to_cvec(val)?),
            b"exec" => exec = Some(to_cvec(val)?),
            b"arg" => {
                if args.len() < MAX_ARGS - 1 {
                    args.push(to_cvec(val)?, GFP_KERNEL)?;
                }
            }
            b"run" => {}
            _ => {}
        }
    }

    let rootfs = rootfs.ok_or(EINVAL)?;
    let exec = exec.ok_or(EINVAL)?;
    let host = match host {
        Some(h) => h,
        None => to_cvec(b"krunc")?,
    };

    // assemble argv = [exec, args...]
    let mut argv: KVec<KVec<u8>> = KVec::new();
    argv.push(exec, GFP_KERNEL)?;
    while !args.is_empty() {
        let a = args.remove(0).map_err(|_| EINVAL)?;
        argv.push(a, GFP_KERNEL)?;
    }

    // hostname copy for the status table (without trailing NUL)
    let mut host_disp: KVec<u8> = KVec::new();
    host_disp.extend_from_slice(&host[..host.len().saturating_sub(1)], GFP_KERNEL)?;

    let ctx = KBox::new(
        ContainerCtx {
            hostname: host,
            rootfs,
            argv,
        },
        GFP_KERNEL,
    )?;
    let raw = ctx.into_foreign();

    // SAFETY: `container_entry` has the required C ABI and `raw` is a freshly
    // leaked `KBox<ContainerCtx>` which it takes ownership of.
    let pid = unsafe { user_mode_thread(container_entry, raw, KRUNC_CLONE_FLAGS) };
    if pid < 0 {
        // The thread was not created; reclaim and drop the context.
        // SAFETY: `raw` was produced by `into_foreign` just above and not consumed.
        drop(unsafe { <KBox<ContainerCtx> as ForeignOwnable>::from_foreign(raw) });
        pr_err!("user_mode_thread failed: {}\n", pid);
        return Err(Error::from_errno(pid));
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    REGISTRY.lock().push(
        Container {
            id,
            pid,
            hostname: host_disp,
        },
        GFP_KERNEL,
    )?;
    pr_info!("started container id={} pid={}\n", id, pid);
    Ok(())
}

fn render_status() -> Result<KVec<u8>> {
    let mut out: KVec<u8> = KVec::new();
    out.extend_from_slice(b"ID    PID      STATE    HOSTNAME\n", GFP_KERNEL)?;
    let guard = REGISTRY.lock();
    for c in guard.as_slice() {
        // Probe liveness with signal 0 (sends nothing, just checks existence).
        // SAFETY: simple FFI call into the vmlinux helper.
        let alive = unsafe { krunc_kill(c.pid, 0) } == 0;
        let state = if alive { "running" } else { "exited" };
        let host = core::str::from_utf8(&c.hostname).unwrap_or("?");
        let line = CString::try_from_fmt(fmt!("{:<5} {:<8} {:<8} {}\n", c.id, c.pid, state, host))?;
        out.extend_from_slice(line.as_bytes(), GFP_KERNEL)?;
    }
    Ok(out)
}

// ----------------------------- the container init ----------------------------

/// Entry point of the container's PID 1, executed in kernel context inside the
/// new namespaces. Sets hostname, enters the rootfs and execs the binary.
///
/// # Safety
/// `arg` must be a `*mut c_void` produced by `KBox::<ContainerCtx>::into_foreign`.
unsafe extern "C" fn container_entry(arg: *mut c_void) -> c_int {
    // SAFETY: by contract `arg` is a leaked `KBox<ContainerCtx>`.
    let ctx = unsafe { <KBox<ContainerCtx> as ForeignOwnable>::from_foreign(arg) };

    // hostname (best effort)
    if ctx.hostname.len() > 1 {
        let hlen = ctx.hostname.len() - 1; // exclude trailing NUL
        // SAFETY: pointer/len describe a valid NUL-terminated buffer.
        unsafe { krunc_set_hostname(ctx.hostname.as_ptr() as *const c_char, hlen) };
    }

    // enter the container rootfs
    // SAFETY: `rootfs` is NUL-terminated.
    let cr = unsafe { krunc_chroot(ctx.rootfs.as_ptr() as *const c_char) };
    if cr != 0 {
        pr_err!("chroot into container rootfs failed: {}\n", cr);
        return cr; // ctx dropped here -> no leak
    }

    // Copy argv onto the stack so the heap context can be freed before exec.
    let mut argbuf = [[0u8; ARG_LEN]; MAX_ARGS];
    let mut argptr = [ptr::null::<c_char>(); MAX_ARGS + 1];
    let n = core::cmp::min(ctx.argv.len(), MAX_ARGS);
    for i in 0..n {
        let src = &ctx.argv[i];
        let l = core::cmp::min(src.len(), ARG_LEN);
        argbuf[i][..l].copy_from_slice(&src[..l]);
        argbuf[i][ARG_LEN - 1] = 0; // guarantee NUL termination
        argptr[i] = argbuf[i].as_ptr() as *const c_char;
    }
    argptr[n] = ptr::null();

    // Minimal default environment.
    let envp: [*const c_char; 5] = [
        b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\0".as_ptr() as *const c_char,
        b"HOME=/\0".as_ptr() as *const c_char,
        b"TERM=linux\0".as_ptr() as *const c_char,
        b"container=krunc\0".as_ptr() as *const c_char,
        ptr::null(),
    ];

    // argv is copied to the stack; free the heap context now.
    drop(ctx);

    if argptr[0].is_null() {
        pr_err!("container has no exec path\n");
        return -22; // -EINVAL
    }

    // Become the container's userspace process. On success `kernel_execve`
    // rewrites this task's registers to enter the new program; it returns 0 and
    // the new program runs when this function returns. A non-zero return is a
    // genuine exec failure.
    // SAFETY: argptr/envp are NUL-terminated arrays of NUL-terminated strings,
    // valid for the duration of the call.
    let rc = unsafe { kernel_execve(argptr[0], argptr.as_ptr(), envp.as_ptr()) };
    if rc != 0 {
        pr_err!("execve failed: {}\n", rc);
    }
    rc
}
