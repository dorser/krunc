// SPDX-License-Identifier: GPL-2.0
//! # krunc — a container runtime in the kernel
//!
//! `krunc` ("kernel runc") is a proof-of-concept container runtime implemented
//! as a Rust kernel module. It performs container *orchestration* — namespace
//! creation, rootfs entry, hostname and process exec — inside the kernel.
//!
//! It exposes two control interfaces on the misc device `/dev/krunc`:
//!
//! * a **text** interface (busybox-friendly) for one-shot containers:
//!   `write()` a line `run rootfs=… host=… exec=… [arg=…]` or `kill <pid>`;
//!   `read()` returns the container table.
//! * an **ioctl** interface implementing an OCI-runtime-style two-phase
//!   lifecycle (`create` / `start` / `state` / `kill` / `delete`) used by the
//!   userspace `krunc` OCI CLI so a higher-level runtime (containerd) can drive
//!   it. `create` sets a container up and **blocks it before exec**; `start`
//!   releases it.
//!
//! The handful of primitives mainline does not export to modules
//! (`user_mode_thread`, `kernel_execve`, plus thin `krunc_*` helpers) come from
//! `kernel/krunc_exports.c`, compiled into vmlinux. All policy lives here.

use core::ptr;
use core::sync::atomic::{AtomicU64, AtomicU8, Ordering};

use kernel::{
    c_str,
    error::Error,
    ffi::{c_char, c_int, c_uint, c_ulong, c_void},
    fs::{File, Kiocb},
    ioctl::_IOC_NR,
    iov::{IovIterDest, IovIterSource},
    miscdevice::{MiscDevice, MiscDeviceOptions, MiscDeviceRegistration},
    prelude::*,
    str::CString,
    sync::Arc,
    transmute::{AsBytes, FromBytes},
    types::ForeignOwnable,
    uaccess::{UserPtr, UserSlice},
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
    /// Create a container init task in fresh namespaces (clones without
    /// CLONE_VM so it does not share the caller's address space). Returns the
    /// new task's pid in the caller's pid namespace, or -errno.
    fn krunc_spawn(
        f: unsafe extern "C" fn(*mut c_void) -> c_int,
        arg: *mut c_void,
        flags: c_ulong,
    ) -> c_int;
    fn kernel_execve(
        filename: *const c_char,
        argv: *const *const c_char,
        envp: *const *const c_char,
    ) -> c_int;
    fn krunc_set_hostname(name: *const c_char, len: usize) -> c_int;
    fn krunc_chroot(path: *const c_char) -> c_int;
    fn krunc_kill(nr: c_int, sig: c_int) -> c_int;
    // msleep() is exported by mainline.
    fn msleep(msecs: c_uint);
}

// clone(2) namespace flags (uapi/linux/sched.h)
const CLONE_NEWNS: c_ulong = 0x0002_0000;
const CLONE_NEWUTS: c_ulong = 0x0400_0000;
const CLONE_NEWIPC: c_ulong = 0x0800_0000;
const CLONE_NEWPID: c_ulong = 0x2000_0000;
const CLONE_NEWNET: c_ulong = 0x4000_0000;
const SIGCHLD: c_ulong = 17;
const SIGKILL: c_int = 9;

const ALL_NS: c_ulong =
    CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET;

// Two-phase create/start gate states.
const ACT_WAIT: u8 = 0; // created, blocked before exec
const ACT_START: u8 = 1; // released -> exec
const ACT_DOOM: u8 = 2; // torn down before start -> exit

// OCI lifecycle states reported by ioctl STATE.
const ST_CREATED: u32 = 0;
const ST_RUNNING: u32 = 1;
const ST_STOPPED: u32 = 2;

const MAX_ARGS: usize = 32;
const MAX_SPEC: usize = 16 * 1024;

/// ioctl command numbers (we match on the _IOC_NR only, so the exact size/dir
/// bits the userspace side encodes do not need to agree precisely).
const NR_CREATE: u32 = 1;
const NR_START: u32 = 2;
const NR_STATE: u32 = 3;
const NR_KILL: u32 = 4;
const NR_DELETE: u32 = 5;

/// ioctl payload shared with the userspace CLI. `#[repr(C)]`, 32 bytes, no
/// padding holes (fields ordered by decreasing alignment).
#[repr(C)]
#[derive(Copy, Clone)]
struct KruncCmd {
    /// userspace pointer to the (text) spec, for CREATE.
    spec_ptr: u64,
    /// container id (out for CREATE; in for START/STATE/KILL/DELETE).
    id: u64,
    /// length of the spec, for CREATE.
    spec_len: u32,
    /// host-visible pid (out for CREATE/STATE).
    pid: i32,
    /// signal number, for KILL.
    sig: i32,
    /// container state (out for STATE).
    state: u32,
}

// SAFETY: `KruncCmd` is `#[repr(C)]` and contains only integers, so every byte
// pattern is a valid value and there are no padding bytes.
unsafe impl FromBytes for KruncCmd {}
// SAFETY: `KruncCmd` has no padding, so all of its bytes are initialized.
unsafe impl AsBytes for KruncCmd {}

/// Shared control block for a paused (two-phase) container. The container init
/// polls `action`; the module sets it from `start`/`delete`.
struct ContainerControl {
    action: AtomicU8,
}

/// Heap context handed to the new task (via `ForeignOwnable`). On a successful
/// `execve` the task never returns, so this is intentionally leaked then (a
/// small, documented per-container cost); on any failure path it is dropped.
struct ContainerCtx {
    hostname: KVec<u8>,        // NUL-terminated
    rootfs: KVec<u8>,          // NUL-terminated
    argv: KVec<KVec<u8>>,      // each NUL-terminated; argv[0] is the binary
    envp: KVec<KVec<u8>>,      // each NUL-terminated; empty -> default env
    ctrl: Option<Arc<ContainerControl>>, // Some -> two-phase (created) container
}

/// A launched container, for status/listing and the OCI lifecycle.
struct Container {
    id: u64,
    pid: i32,
    hostname: KVec<u8>,
    ctrl: Option<Arc<ContainerControl>>,
    started: bool,
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

struct KruncDevice;

#[vtable]
impl MiscDevice for KruncDevice {
    type Ptr = KBox<KruncDevice>;

    fn open(_file: &File, _misc: &MiscDeviceRegistration<Self>) -> Result<KBox<KruncDevice>> {
        Ok(KBox::new(KruncDevice, GFP_KERNEL)?)
    }

    /// Text control: a single command line (`run …` or `kill <pid>`).
    fn write_iter(_kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterSource<'_>) -> Result<usize> {
        let mut buf: KVec<u8> = KVec::new();
        let len = iov.copy_from_iter_vec(&mut buf, GFP_KERNEL)?;
        if buf.len() > MAX_SPEC {
            return Err(EINVAL);
        }
        handle_text_command(&buf)?;
        Ok(len)
    }

    /// Text status: the container table.
    fn read_iter(mut kiocb: Kiocb<'_, Self::Ptr>, iov: &mut IovIterDest<'_>) -> Result<usize> {
        let out = render_status()?;
        let read = iov.simple_read_from_buffer(kiocb.ki_pos_mut(), &out)?;
        Ok(read)
    }

    /// OCI lifecycle control plane.
    fn ioctl(_device: &KruncDevice, _file: &File, cmd: u32, arg: usize) -> Result<isize> {
        ioctl_dispatch(cmd, arg)
    }
}

// =============================== ioctl plane ================================

fn ioctl_dispatch(cmd: u32, arg: usize) -> Result<isize> {
    let size = core::mem::size_of::<KruncCmd>();
    let mut c: KruncCmd = UserSlice::new(UserPtr::from_addr(arg), size)
        .reader()
        .read::<KruncCmd>()?;

    match _IOC_NR(cmd) {
        NR_CREATE => {
            // Copy the spec text in from userspace.
            let mut spec: KVec<u8> = KVec::new();
            if c.spec_len as usize > MAX_SPEC {
                return Err(EINVAL);
            }
            UserSlice::new(UserPtr::from_addr(c.spec_ptr as usize), c.spec_len as usize)
                .read_all(&mut spec, GFP_KERNEL)?;
            let (id, pid) = create_from_oci(&spec)?;
            c.id = id;
            c.pid = pid;
        }
        NR_START => start_container(c.id)?,
        NR_STATE => {
            let (state, pid) = container_state(c.id)?;
            c.state = state;
            c.pid = pid;
        }
        NR_KILL => {
            let sig = if c.sig != 0 { c.sig } else { SIGKILL };
            kill_container(c.id, sig)?;
        }
        NR_DELETE => delete_container(c.id)?,
        _ => return Err(ENOTTY),
    }

    // Write the (possibly updated) command struct back out.
    UserSlice::new(UserPtr::from_addr(arg), size)
        .writer()
        .write::<KruncCmd>(&c)?;
    Ok(0)
}

fn start_container(id: u64) -> Result {
    let mut g = REGISTRY.lock();
    for c in g.iter_mut() {
        if c.id == id {
            if let Some(ctrl) = &c.ctrl {
                ctrl.action.store(ACT_START, Ordering::Release);
            }
            c.started = true;
            pr_info!("started container id={} pid={}\n", id, c.pid);
            return Ok(());
        }
    }
    Err(ENOENT)
}

fn container_state(id: u64) -> Result<(u32, i32)> {
    let g = REGISTRY.lock();
    for c in g.as_slice() {
        if c.id == id {
            let state = if !c.started {
                ST_CREATED
            } else if is_alive(c.pid) {
                ST_RUNNING
            } else {
                ST_STOPPED
            };
            return Ok((state, c.pid));
        }
    }
    Err(ENOENT)
}

fn kill_container(id: u64, sig: i32) -> Result {
    let pid = {
        let g = REGISTRY.lock();
        g.as_slice()
            .iter()
            .find(|c| c.id == id)
            .map(|c| c.pid)
            .ok_or(ENOENT)?
    };
    // SAFETY: FFI call into the vmlinux helper.
    let rc = unsafe { krunc_kill(pid, sig) };
    if rc < 0 {
        return Err(Error::from_errno(rc));
    }
    Ok(())
}

fn delete_container(id: u64) -> Result {
    let mut g = REGISTRY.lock();
    let idx = g
        .as_slice()
        .iter()
        .position(|c| c.id == id)
        .ok_or(ENOENT)?;
    let c = &g.as_slice()[idx];
    if !c.started {
        // never started: release the blocked init so it exits instead of execs.
        if let Some(ctrl) = &c.ctrl {
            ctrl.action.store(ACT_DOOM, Ordering::Release);
        }
    } else if is_alive(c.pid) {
        // SAFETY: FFI call into the vmlinux helper.
        unsafe { krunc_kill(c.pid, SIGKILL) };
    }
    g.remove(idx).map_err(|_| EINVAL)?;
    pr_info!("deleted container id={}\n", id);
    Ok(())
}

/// Liveness probe: signal 0 sends nothing, just checks the pid still exists.
fn is_alive(pid: i32) -> bool {
    // SAFETY: FFI call into the vmlinux helper.
    unsafe { krunc_kill(pid, 0) == 0 }
}

// ============================== text plane =================================

fn handle_text_command(buf: &[u8]) -> Result {
    let line = trim(buf);
    if line.is_empty() {
        return Err(EINVAL);
    }
    if let Some(rest) = line.strip_prefix(b"kill") {
        let rest = rest.strip_prefix(b"=").unwrap_or(rest);
        let pid = parse_i32(rest).ok_or(EINVAL)?;
        // SAFETY: FFI call into the vmlinux helper.
        let rc = unsafe { krunc_kill(pid, SIGKILL) };
        if rc < 0 {
            return Err(Error::from_errno(rc));
        }
        REGISTRY.lock().retain(|c| c.pid != pid);
        pr_info!("killed container pid {}\n", pid);
        return Ok(());
    }
    // `run …` (one-shot: created and started immediately)
    let (hostname, rootfs, argv, envp, flags) = parse_run_line(line)?;
    let (id, pid) = spawn(hostname, rootfs, argv, envp, flags, false)?;
    pr_info!("started container id={} pid={}\n", id, pid);
    Ok(())
}

fn render_status() -> Result<KVec<u8>> {
    let mut out: KVec<u8> = KVec::new();
    out.extend_from_slice(b"ID    PID      STATE    HOSTNAME\n", GFP_KERNEL)?;
    let guard = REGISTRY.lock();
    for c in guard.as_slice() {
        let state = if !c.started {
            "created"
        } else if is_alive(c.pid) {
            "running"
        } else {
            "exited"
        };
        let host = core::str::from_utf8(&c.hostname).unwrap_or("?");
        let line = CString::try_from_fmt(fmt!("{:<5} {:<8} {:<8} {}\n", c.id, c.pid, state, host))?;
        out.extend_from_slice(line.as_bytes(), GFP_KERNEL)?;
    }
    Ok(out)
}

// ============================ spec parsing ================================

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

fn to_cvec(s: &[u8]) -> Result<KVec<u8>> {
    let mut v = KVec::with_capacity(s.len() + 1, GFP_KERNEL)?;
    v.extend_from_slice(s, GFP_KERNEL)?;
    v.push(0, GFP_KERNEL)?;
    Ok(v)
}

fn ns_flag(name: &[u8]) -> c_ulong {
    match name {
        b"pid" => CLONE_NEWPID,
        b"mount" | b"mnt" => CLONE_NEWNS,
        b"uts" => CLONE_NEWUTS,
        b"ipc" => CLONE_NEWIPC,
        b"network" | b"net" => CLONE_NEWNET,
        _ => 0, // user/cgroup/time namespaces are not handled (PoC)
    }
}

type Spec = (KVec<u8>, KVec<u8>, KVec<KVec<u8>>, KVec<KVec<u8>>, c_ulong);

/// Text `run` line: whitespace-separated `key=value` tokens (no spaces in
/// values). `exec` is argv[0]; each `arg=` appends. All five namespaces.
fn parse_run_line(line: &[u8]) -> Result<Spec> {
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
        let (key, val) = split_kv(&line[start..i]);
        match key {
            b"rootfs" => rootfs = Some(to_cvec(val)?),
            b"host" | b"hostname" => host = Some(to_cvec(val)?),
            b"exec" => exec = Some(to_cvec(val)?),
            b"arg" => {
                if args.len() < MAX_ARGS - 1 {
                    args.push(to_cvec(val)?, GFP_KERNEL)?;
                }
            }
            _ => {}
        }
    }

    let rootfs = rootfs.ok_or(EINVAL)?;
    let exec = exec.ok_or(EINVAL)?;
    let host = match host {
        Some(h) => h,
        None => to_cvec(b"krunc")?,
    };
    let mut argv: KVec<KVec<u8>> = KVec::new();
    argv.push(exec, GFP_KERNEL)?;
    drain_into(&mut args, &mut argv)?;
    Ok((host, rootfs, argv, KVec::new(), ALL_NS | SIGCHLD))
}

/// OCI spec from the CLI: newline-separated `key=value` lines (values may
/// contain spaces). Keys: `rootfs`, `host`, `arg` (repeatable, in order =
/// argv), `env` (repeatable), `ns` (comma list of namespaces).
fn parse_oci_spec(spec: &[u8]) -> Result<Spec> {
    let mut rootfs: Option<KVec<u8>> = None;
    let mut host: Option<KVec<u8>> = None;
    let mut argv: KVec<KVec<u8>> = KVec::new();
    let mut envp: KVec<KVec<u8>> = KVec::new();
    let mut flags: c_ulong = 0;
    let mut have_ns = false;

    for raw in spec.split(|&b| b == b'\n') {
        let line = trim(raw);
        if line.is_empty() {
            continue;
        }
        let (key, val) = split_kv(line);
        match key {
            b"rootfs" => rootfs = Some(to_cvec(val)?),
            b"host" | b"hostname" => host = Some(to_cvec(val)?),
            b"arg" => {
                if argv.len() < MAX_ARGS - 1 {
                    argv.push(to_cvec(val)?, GFP_KERNEL)?;
                }
            }
            b"env" => {
                if envp.len() < MAX_ARGS - 1 {
                    envp.push(to_cvec(val)?, GFP_KERNEL)?;
                }
            }
            b"ns" => {
                have_ns = true;
                for n in val.split(|&b| b == b',') {
                    flags |= ns_flag(trim(n));
                }
            }
            _ => {}
        }
    }

    let rootfs = rootfs.ok_or(EINVAL)?;
    if argv.is_empty() {
        return Err(EINVAL);
    }
    let host = match host {
        Some(h) => h,
        None => to_cvec(b"krunc")?,
    };
    if !have_ns {
        flags = ALL_NS;
    }
    Ok((host, rootfs, argv, envp, flags | SIGCHLD))
}

fn split_kv(tok: &[u8]) -> (&[u8], &[u8]) {
    match tok.iter().position(|&b| b == b'=') {
        Some(p) => (&tok[..p], &tok[p + 1..]),
        None => (tok, &tok[tok.len()..]),
    }
}

fn drain_into(src: &mut KVec<KVec<u8>>, dst: &mut KVec<KVec<u8>>) -> Result {
    while !src.is_empty() {
        let a = src.remove(0).map_err(|_| EINVAL)?;
        dst.push(a, GFP_KERNEL)?;
    }
    Ok(())
}

// ============================ spawn / init ================================

fn create_from_oci(spec: &[u8]) -> Result<(u64, i32)> {
    let (hostname, rootfs, argv, envp, flags) = parse_oci_spec(spec)?;
    spawn(hostname, rootfs, argv, envp, flags, true)
}

/// Create the container init task. If `paused`, it blocks before exec until
/// `start`. Returns `(id, host_pid)`.
fn spawn(
    hostname: KVec<u8>,
    rootfs: KVec<u8>,
    argv: KVec<KVec<u8>>,
    envp: KVec<KVec<u8>>,
    flags: c_ulong,
    paused: bool,
) -> Result<(u64, i32)> {
    let ctrl = if paused {
        Some(Arc::new(
            ContainerControl {
                action: AtomicU8::new(ACT_WAIT),
            },
            GFP_KERNEL,
        )?)
    } else {
        None
    };

    let mut host_disp: KVec<u8> = KVec::new();
    host_disp.extend_from_slice(&hostname[..hostname.len().saturating_sub(1)], GFP_KERNEL)?;

    let ctx = KBox::new(
        ContainerCtx {
            hostname,
            rootfs,
            argv,
            envp,
            ctrl: ctrl.as_ref().map(|a| a.clone()),
        },
        GFP_KERNEL,
    )?;
    let raw = ctx.into_foreign();

    // SAFETY: `container_entry` has the required C ABI and takes ownership of
    // `raw` (a leaked `KBox<ContainerCtx>`).
    let pid = unsafe { krunc_spawn(container_entry, raw, flags) };
    if pid < 0 {
        // The thread was not created; reclaim and drop the context.
        // SAFETY: `raw` was produced by `into_foreign` just above and unused.
        drop(unsafe { <KBox<ContainerCtx> as ForeignOwnable>::from_foreign(raw) });
        pr_err!("krunc_spawn failed: {}\n", pid);
        return Err(Error::from_errno(pid));
    }

    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    REGISTRY.lock().push(
        Container {
            id,
            pid,
            hostname: host_disp,
            ctrl,
            started: !paused,
        },
        GFP_KERNEL,
    )?;
    Ok((id, pid))
}

/// The container's PID 1, run in kernel context inside the new namespaces.
///
/// # Safety
/// `arg` must be a `*mut c_void` from `KBox::<ContainerCtx>::into_foreign`.
unsafe extern "C" fn container_entry(arg: *mut c_void) -> c_int {
    // SAFETY: by contract `arg` is a leaked `KBox<ContainerCtx>`.
    let ctx = unsafe { <KBox<ContainerCtx> as ForeignOwnable>::from_foreign(arg) };

    if ctx.hostname.len() > 1 {
        let hlen = ctx.hostname.len() - 1; // exclude trailing NUL
        // SAFETY: valid NUL-terminated buffer.
        unsafe { krunc_set_hostname(ctx.hostname.as_ptr() as *const c_char, hlen) };
    }

    // SAFETY: `rootfs` is NUL-terminated.
    let cr = unsafe { krunc_chroot(ctx.rootfs.as_ptr() as *const c_char) };
    if cr != 0 {
        pr_err!("chroot into container rootfs failed: {}\n", cr);
        return cr; // ctx dropped here -> freed
    }

    // Two-phase: a created container blocks here until start (or delete).
    if let Some(ctrl) = ctx.ctrl.as_ref() {
        loop {
            match ctrl.action.load(Ordering::Acquire) {
                ACT_WAIT => unsafe { msleep(10) },
                ACT_DOOM => return 0, // torn down before start; ctx dropped -> freed
                _ => break,
            }
        }
    }

    // Build argv/envp pointer arrays (into ctx's buffers, which stay valid for
    // the execve call). On a successful exec this function never returns, so
    // `ctx` is leaked (small, documented); any failure path drops it.
    let mut argv_ptr = [ptr::null::<c_char>(); MAX_ARGS + 1];
    let n = core::cmp::min(ctx.argv.len(), MAX_ARGS);
    for i in 0..n {
        argv_ptr[i] = ctx.argv[i].as_ptr() as *const c_char;
    }
    argv_ptr[n] = ptr::null();
    if argv_ptr[0].is_null() {
        pr_err!("container has no exec path\n");
        return -22; // -EINVAL
    }

    let default_env: [*const c_char; 5] = [
        b"PATH=/bin:/sbin:/usr/bin:/usr/sbin\0".as_ptr() as *const c_char,
        b"HOME=/\0".as_ptr() as *const c_char,
        b"TERM=linux\0".as_ptr() as *const c_char,
        b"container=krunc\0".as_ptr() as *const c_char,
        ptr::null(),
    ];
    let mut env_ptr = [ptr::null::<c_char>(); MAX_ARGS + 1];
    let envp: *const *const c_char = if ctx.envp.is_empty() {
        default_env.as_ptr()
    } else {
        let m = core::cmp::min(ctx.envp.len(), MAX_ARGS);
        for i in 0..m {
            env_ptr[i] = ctx.envp[i].as_ptr() as *const c_char;
        }
        env_ptr[m] = ptr::null();
        env_ptr.as_ptr()
    };

    // SAFETY: argv/envp are NUL-terminated arrays of NUL-terminated strings,
    // valid for the duration of the call. On success the kernel rewrites this
    // task's registers to enter the new program and returns 0.
    let rc = unsafe { kernel_execve(argv_ptr[0], argv_ptr.as_ptr(), envp) };
    if rc != 0 {
        pr_err!("execve failed: {}\n", rc);
    }
    rc
}
