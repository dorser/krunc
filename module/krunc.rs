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
    /// Apply privilege confinement to the current task before exec: lower the
    /// capability sets to `cap_mask` (0 = leave untouched) and optionally set
    /// no_new_privs.
    fn krunc_apply_creds(
        bset: u64,
        eff: u64,
        perm: u64,
        inh: u64,
        amb: u64,
        uid: c_uint,
        gid: c_uint,
        no_new_privs: c_int,
    ) -> c_int;
    /// Mount `fstype` from `dev` onto `dir` in the current task's mount
    /// namespace (e.g. a fresh /proc for the container).
    fn krunc_mount(
        dev: *const c_char,
        dir: *const c_char,
        fstype: *const c_char,
        flags: c_ulong,
    ) -> c_int;
    /// Install a kernel-resident classic-BPF seccomp program (`len` instructions)
    /// on the current task. Must be called after no_new_privs is set.
    fn krunc_seccomp_install(insns: *const c_void, len: c_uint) -> c_int;
    /// Apply one resource limit (`setrlimit`) to the current task before exec.
    fn krunc_apply_rlimit(resource: c_uint, soft: u64, hard: u64) -> c_int;
    /// Set the current task's OOM-killer score adjustment before exec.
    fn krunc_set_oom_score_adj(adj: c_int);
    /// Seal a Landlock domain allowing writes only beneath `paths` (`n` entries).
    fn krunc_landlock_restrict_writes(paths: *const *const c_char, n: c_int) -> c_int;
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

// mount(2) flags (uapi/linux/mount.h) used for path confinement.
const MS_RDONLY: c_ulong = 1;
const MS_REMOUNT: c_ulong = 32;
const MS_BIND: c_ulong = 4096;
const MS_REC: c_ulong = 16384;
const MS_PRIVATE: c_ulong = 1 << 18;

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
/// Maximum number of rlimit entries accepted from the spec.
const MAX_RLIMITS: usize = 32;
/// Maximum number of mount entries accepted from the spec.
const MAX_MOUNTS: usize = 64;
/// Stack-array bound for the Landlock writable-path pointer list.
const MAX_PATHS_ARR: usize = 64;
/// Maximum length of a single string field in the binary spec.
const MAX_STR: usize = 4096;
/// krunc-abi wire magic and version (see the `krunc-abi` crate).
const ABI_VERSION: u32 = 1;
/// `OPT_NO_NEW_PRIVS` from the krunc-abi `flags` section.
const OPT_NO_NEW_PRIVS: u64 = 1 << 0;

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
    cap_sets: CapSets,         // the five capability sets applied before exec
    no_new_privs: bool,        // set no_new_privs before exec
    seccomp: KVec<u8>,         // compiled sock_filter[] blob (empty = no seccomp)
    masked: KVec<KVec<u8>>,    // paths over-mounted to be inaccessible (each NUL-terminated)
    readonly: KVec<KVec<u8>>,  // paths remounted read-only (each NUL-terminated)
    rlimits: KVec<RLimit>,     // resource limits applied before exec
    oom_score_adj: Option<i32>, // OOM score adjustment applied before exec
    uid: u32,                  // target uid (process.user.uid)
    gid: u32,                  // target gid (process.user.gid)
    mounts: KVec<MountSpec>,   // mounts to perform (empty -> default /proc + /sys)
    landlock_rw: KVec<KVec<u8>>, // Landlock writable paths (empty = no fs seal)
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
            let (id, pid) = create_from_blob(&spec)?;
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
    let (id, pid) = spawn(
        hostname,
        rootfs,
        argv,
        envp,
        flags,
        false,
        CapSets::default(),
        false,
        KVec::new(),
        KVec::new(),
        KVec::new(),
        KVec::new(),
        None,
        0,
        0,
        KVec::new(),
        KVec::new(),
    )?;
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

type Spec = (KVec<u8>, KVec<u8>, KVec<KVec<u8>>, KVec<KVec<u8>>, c_ulong);

fn split_kv(tok: &[u8]) -> (&[u8], &[u8]) {
    match tok.iter().position(|&b| b == b'=') {
        Some(p) => (&tok[..p], &tok[p + 1..]),
        None => (tok, &tok[tok.len()..]),
    }
}

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

/// A bounds-checked, panic-free cursor over the binary spec buffer.
struct BReader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> BReader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn rem(&self) -> usize {
        self.b.len() - self.p
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if n > self.rem() {
            return Err(EINVAL);
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().map_err(|_| EINVAL)?))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().map_err(|_| EINVAL)?))
    }
    fn u64(&mut self) -> Result<u64> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().map_err(|_| EINVAL)?))
    }
}

/// Fields decoded from the krunc-abi binary spec. The kernel performs only this
/// trivial, strict, bounds-checked parse — never any JSON parsing.
struct DecodedSpec {
    hostname: KVec<u8>,
    rootfs: KVec<u8>,
    argv: KVec<KVec<u8>>,
    envp: KVec<KVec<u8>>,
    ns: u32,
    cap_bounding: u64,
    cap_effective: u64,
    cap_permitted: u64,
    cap_inheritable: u64,
    cap_ambient: u64,
    flags: u64,
    seccomp: KVec<u8>,
    masked: KVec<KVec<u8>>,
    readonly: KVec<KVec<u8>>,
    rlimits: KVec<RLimit>,
    oom_score_adj: Option<i32>,
    uid: u32,
    gid: u32,
    mounts: KVec<MountSpec>,
    landlock_rw: KVec<KVec<u8>>,
}

/// The five Linux capability sets applied to the container before exec.
#[derive(Clone, Copy, Default)]
struct CapSets {
    bounding: u64,
    effective: u64,
    permitted: u64,
    inheritable: u64,
    ambient: u64,
}

/// A decoded resource limit (`setrlimit`).
#[derive(Clone, Copy)]
struct RLimit {
    resource: u32,
    soft: u64,
    hard: u64,
}

/// A decoded mount (each path NUL-terminated; `fs_type`/`source` of length <= 1
/// mean "none", passed to the helper as NULL).
struct MountSpec {
    destination: KVec<u8>,
    fs_type: KVec<u8>,
    source: KVec<u8>,
    flags: c_ulong,
}

fn read_lenbytes<'a>(sr: &mut BReader<'a>) -> Result<&'a [u8]> {
    let l = sr.u32()? as usize;
    if l > MAX_STR {
        return Err(EINVAL);
    }
    sr.take(l)
}

fn read_mounts_k(sr: &mut BReader<'_>) -> Result<KVec<MountSpec>> {
    let n = sr.u32()? as usize;
    let mut v: KVec<MountSpec> = KVec::new();
    for _ in 0..n {
        let dest = to_cvec(read_lenbytes(sr)?)?;
        let fs_type = to_cvec(read_lenbytes(sr)?)?;
        let source = to_cvec(read_lenbytes(sr)?)?;
        let flags = sr.u64()? as c_ulong;
        if v.len() < MAX_MOUNTS {
            v.push(MountSpec { destination: dest, fs_type, source, flags }, GFP_KERNEL)?;
        }
    }
    Ok(v)
}

fn read_rlimits_k(sr: &mut BReader<'_>) -> Result<KVec<RLimit>> {
    let n = sr.u32()? as usize;
    let mut v: KVec<RLimit> = KVec::new();
    for _ in 0..n {
        let resource = sr.u32()?;
        let soft = sr.u64()?;
        let hard = sr.u64()?;
        if v.len() < MAX_RLIMITS {
            v.push(RLimit { resource, soft, hard }, GFP_KERNEL)?;
        }
    }
    Ok(v)
}

fn read_strvec_k(sr: &mut BReader<'_>) -> Result<KVec<KVec<u8>>> {
    let n = sr.u32()? as usize;
    let mut v: KVec<KVec<u8>> = KVec::new();
    for _ in 0..n {
        let l = sr.u32()? as usize;
        if l > MAX_STR {
            return Err(EINVAL);
        }
        let bytes = sr.take(l)?;
        if v.len() < MAX_ARGS - 1 {
            v.push(to_cvec(bytes)?, GFP_KERNEL)?;
        }
    }
    Ok(v)
}

/// Decode the krunc-abi binary spec (see the `krunc-abi` crate for the wire
/// format). Strict and total: never panics, rejects any out-of-bounds length,
/// and ignores unknown section tags (forward-compatible).
fn decode_spec(buf: &[u8]) -> Result<DecodedSpec> {
    if buf.len() > MAX_SPEC {
        return Err(EINVAL);
    }
    let mut r = BReader::new(buf);
    if r.take(4)? != &b"KRNC"[..] {
        return Err(EINVAL);
    }
    if r.u32()? != ABI_VERSION {
        return Err(EINVAL);
    }
    let _op = r.u32()?; // op is also conveyed by the ioctl number
    let count = r.u32()? as usize;
    if count > MAX_SPEC / 8 {
        return Err(EINVAL);
    }
    let mut d = DecodedSpec {
        hostname: KVec::new(),
        rootfs: KVec::new(),
        argv: KVec::new(),
        envp: KVec::new(),
        ns: 0,
        cap_bounding: 0,
        cap_effective: 0,
        cap_permitted: 0,
        cap_inheritable: 0,
        cap_ambient: 0,
        flags: 0,
        seccomp: KVec::new(),
        masked: KVec::new(),
        readonly: KVec::new(),
        rlimits: KVec::new(),
        oom_score_adj: None,
        uid: 0,
        gid: 0,
        mounts: KVec::new(),
        landlock_rw: KVec::new(),
    };
    for _ in 0..count {
        let tag = r.u16()?;
        let _pad = r.u16()?;
        let len = r.u32()? as usize;
        if len > r.rem() {
            return Err(EINVAL);
        }
        let payload = r.take(len)?;
        let mut sr = BReader::new(payload);
        match tag {
            1 => d.rootfs = to_cvec(payload)?,     // ROOTFS
            2 => d.hostname = to_cvec(payload)?,   // HOSTNAME
            3 => d.argv = read_strvec_k(&mut sr)?, // ARGV
            4 => d.envp = read_strvec_k(&mut sr)?, // ENV
            5 => d.ns = sr.u32()?,                 // NAMESPACES
            8 => d.flags = sr.u64()?,              // FLAGS
            9 => d.cap_bounding = sr.u64()?,       // CAP_BOUNDING
            15 => {
                // CAP_SETS: effective, permitted, inheritable, ambient.
                d.cap_effective = sr.u64()?;
                d.cap_permitted = sr.u64()?;
                d.cap_inheritable = sr.u64()?;
                d.cap_ambient = sr.u64()?;
            }
            10 => {
                // SECCOMP: a raw sock_filter[] blob; copy verbatim (8 bytes/insn).
                let mut v: KVec<u8> = KVec::new();
                v.extend_from_slice(payload, GFP_KERNEL)?;
                d.seccomp = v;
            }
            11 => d.masked = read_strvec_k(&mut sr)?, // MASKED_PATHS
            12 => d.readonly = read_strvec_k(&mut sr)?, // RO_PATHS
            13 => d.rlimits = read_rlimits_k(&mut sr)?, // RLIMITS
            14 => d.oom_score_adj = Some(sr.u32()? as i32), // OOM_SCORE_ADJ
            16 => {
                // USER: target uid, gid.
                d.uid = sr.u32()?;
                d.gid = sr.u32()?;
            }
            17 => d.mounts = read_mounts_k(&mut sr)?, // MOUNTS
            18 => d.landlock_rw = read_strvec_k(&mut sr)?, // LANDLOCK_RW
            // tags 6/7 (uid/gid maps) land in a later milestone.
            _ => {}
        }
    }
    Ok(d)
}

fn drain_into(src: &mut KVec<KVec<u8>>, dst: &mut KVec<KVec<u8>>) -> Result {
    while !src.is_empty() {
        let a = src.remove(0).map_err(|_| EINVAL)?;
        dst.push(a, GFP_KERNEL)?;
    }
    Ok(())
}

// ============================ spawn / init ================================

fn create_from_blob(spec: &[u8]) -> Result<(u64, i32)> {
    let d = decode_spec(spec)?;
    if d.rootfs.len() <= 1 || d.argv.is_empty() {
        return Err(EINVAL);
    }
    let host = if d.hostname.len() > 1 {
        d.hostname
    } else {
        to_cvec(b"krunc")?
    };
    let ns = if d.ns != 0 { d.ns as c_ulong } else { ALL_NS };
    let no_new_privs = d.flags & OPT_NO_NEW_PRIVS != 0;
    let cap_sets = CapSets {
        bounding: d.cap_bounding,
        effective: d.cap_effective,
        permitted: d.cap_permitted,
        inheritable: d.cap_inheritable,
        ambient: d.cap_ambient,
    };
    spawn(
        host,
        d.rootfs,
        d.argv,
        d.envp,
        ns | SIGCHLD,
        true,
        cap_sets,
        no_new_privs,
        d.seccomp,
        d.masked,
        d.readonly,
        d.rlimits,
        d.oom_score_adj,
        d.uid,
        d.gid,
        d.mounts,
        d.landlock_rw,
    )
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
    cap_sets: CapSets,
    no_new_privs: bool,
    seccomp: KVec<u8>,
    masked: KVec<KVec<u8>>,
    readonly: KVec<KVec<u8>>,
    rlimits: KVec<RLimit>,
    oom_score_adj: Option<i32>,
    uid: u32,
    gid: u32,
    mounts: KVec<MountSpec>,
    landlock_rw: KVec<KVec<u8>>,
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
            cap_sets,
            no_new_privs,
            seccomp,
            masked,
            readonly,
            rlimits,
            oom_score_adj,
            uid,
            gid,
            mounts,
            landlock_rw,
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

/// Apply filesystem confinement in the container's (CLONE_NEWNS) mount
/// namespace: mask each `masked` path and remount each `readonly` path
/// read-only. Best-effort and total — a path that does not exist is skipped,
/// matching the OCI runtime semantics. Because the over-mounts live in the
/// container's own mount namespace and are installed while privileged, a later
/// compromised workload (with dropped capabilities) cannot remove them.
fn apply_path_confinement(masked: &KVec<KVec<u8>>, readonly: &KVec<KVec<u8>>) {
    let devnull = c"/dev/null".as_ptr() as *const c_char;
    let tmpfs = c"tmpfs".as_ptr() as *const c_char;

    for i in 0..masked.len() {
        let p = &masked[i];
        if p.len() <= 1 {
            continue; // empty / just the NUL terminator
        }
        let path = p.as_ptr() as *const c_char;
        // Bind /dev/null over the target (the file case: reads see nothing,
        // writes are inert). SAFETY: all pointers are NUL-terminated C strings
        // valid for the call; the helper only reads them.
        let rc = unsafe { krunc_mount(devnull, path, ptr::null(), MS_BIND) };
        if rc != 0 {
            // The target is likely a directory: overlay an empty read-only
            // tmpfs instead. SAFETY: as above.
            unsafe { krunc_mount(tmpfs, path, tmpfs, MS_RDONLY) };
        }
    }

    for i in 0..readonly.len() {
        let p = &readonly[i];
        if p.len() <= 1 {
            continue;
        }
        let path = p.as_ptr() as *const c_char;
        // A bind and a flag change cannot be combined in one mount(2): first
        // bind the path onto itself, then remount it read-only.
        // SAFETY: `path` is a NUL-terminated C string valid for both calls.
        let rc = unsafe { krunc_mount(path, path, ptr::null(), MS_BIND) };
        if rc == 0 {
            // SAFETY: as above.
            unsafe {
                krunc_mount(ptr::null(), path, ptr::null(), MS_REMOUNT | MS_BIND | MS_RDONLY)
            };
        }
    }
}

/// Perform the container's configured mounts in order, in its private mount
/// namespace while still privileged. If none are configured, fall back to a
/// private `/proc` + `/sys` (what an unconfigured container still needs).
fn apply_mounts(mounts: &KVec<MountSpec>) {
    if mounts.is_empty() {
        // SAFETY: FFI calls with NUL-terminated C string literals.
        unsafe {
            krunc_mount(
                c"proc".as_ptr() as *const c_char,
                c"/proc".as_ptr() as *const c_char,
                c"proc".as_ptr() as *const c_char,
                0,
            );
            krunc_mount(
                c"sysfs".as_ptr() as *const c_char,
                c"/sys".as_ptr() as *const c_char,
                c"sysfs".as_ptr() as *const c_char,
                0,
            );
        }
        return;
    }

    for i in 0..mounts.len() {
        let m = &mounts[i];
        if m.destination.len() <= 1 {
            continue;
        }
        let dest = m.destination.as_ptr() as *const c_char;
        // fs_type / source of length <= 1 are "none" -> NULL (e.g. bind mounts).
        let src = if m.source.len() > 1 {
            m.source.as_ptr() as *const c_char
        } else {
            ptr::null()
        };
        let typ = if m.fs_type.len() > 1 {
            m.fs_type.as_ptr() as *const c_char
        } else {
            ptr::null()
        };
        // SAFETY: dest/src/typ are NUL-terminated C strings valid for the call.
        let rc = unsafe { krunc_mount(src, dest, typ, m.flags) };
        if rc != 0 {
            pr_err!("krunc: mount #{} failed: {}\n", i, rc);
        }
    }
}

/// Seal a Landlock write-restrict domain granting writes only beneath the given
/// paths. Applied after no_new_privs so it is un-relaxable for the container's
/// life. Returns 0 (or leaves the container running unsealed only if Landlock is
/// absent — `-ENOSYS`, which we tolerate so a non-Landlock kernel still boots).
fn apply_landlock(rw: &KVec<KVec<u8>>) -> c_int {
    if rw.is_empty() {
        return 0;
    }
    let mut ptrs = [ptr::null::<c_char>(); MAX_PATHS_ARR];
    let n = core::cmp::min(rw.len(), MAX_PATHS_ARR);
    for i in 0..n {
        ptrs[i] = rw[i].as_ptr() as *const c_char;
    }
    // SAFETY: `ptrs[..n]` are NUL-terminated C strings valid for the call; the
    // helper only reads them.
    unsafe { krunc_landlock_restrict_writes(ptrs.as_ptr(), n as c_int) }
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

    // Make the container's whole mount tree private *before* we mount anything,
    // so none of the mounts we create (/proc, /sys, masks, read-only binds)
    // propagate back to the host's mount namespace, and host mount events do not
    // leak in. This is runc's first setup step; it operates only on this task's
    // CLONE_NEWNS namespace.
    // SAFETY: FFI call with a NUL-terminated path; dev/fstype are unused here.
    unsafe {
        krunc_mount(
            ptr::null(),
            c"/".as_ptr() as *const c_char,
            ptr::null(),
            MS_REC | MS_PRIVATE,
        );
    }

    // Perform the container's mounts (config-driven, in order), while still
    // privileged, in its CLONE_NEWNS mount namespace. The confined container
    // itself cannot do this once capabilities are dropped, so the kernel sets
    // them up here. With no mounts configured this defaults to /proc + /sys.
    apply_mounts(&ctx.mounts);

    // Filesystem confinement, applied while still privileged so a compromised
    // workload cannot undo it later (it lives in the container's mount namespace
    // and outlives setup): mask sensitive paths and remount others read-only.
    // These neutralise classic post-setup escape vectors (e.g. writing
    // /proc/sysrq-trigger or /proc/sys/kernel/core_pattern).
    apply_path_confinement(&ctx.masked, &ctx.readonly);

    // Resource limits and OOM score, applied while still privileged (so any
    // hard limit can be set) and before exec, so they bound the workload from
    // its first instruction.
    for i in 0..ctx.rlimits.len() {
        let rl = ctx.rlimits[i];
        // SAFETY: FFI call into the vmlinux helper, operating on `current`.
        let rc = unsafe { krunc_apply_rlimit(rl.resource as c_uint, rl.soft, rl.hard) };
        if rc != 0 {
            pr_err!("krunc: rlimit {} rejected: {}\n", rl.resource, rc);
        }
    }
    if let Some(adj) = ctx.oom_score_adj {
        // SAFETY: FFI call into the vmlinux helper, operating on `current`.
        unsafe { krunc_set_oom_score_adj(adj as c_int) };
    }

    // Privilege confinement, applied atomically in kernel context just before
    // exec: the capability ceiling + no_new_privs are in force for the very
    // first userspace instruction, with no intermediate userspace process in
    // which capabilities could leak.
    // SAFETY: FFI call into the vmlinux helper, operating on `current`.
    unsafe {
        krunc_apply_creds(
            ctx.cap_sets.bounding,
            ctx.cap_sets.effective,
            ctx.cap_sets.permitted,
            ctx.cap_sets.inheritable,
            ctx.cap_sets.ambient,
            ctx.uid as c_uint,
            ctx.gid as c_uint,
            if ctx.no_new_privs { 1 } else { 0 },
        )
    };

    // Sealed syscall policy: install the compiled seccomp program now, after
    // no_new_privs is set, so it is in force for the very first userspace
    // instruction and (being under no_new_privs) cannot be relaxed for the
    // container's whole life. This removes the entry point for entire classes of
    // kernel-exploit escapes. The blob is a sock_filter[] (8 bytes per insn).
    if ctx.seccomp.len() >= 8 && ctx.seccomp.len() % 8 == 0 {
        let count = (ctx.seccomp.len() / 8) as c_uint;
        // SAFETY: `ctx.seccomp` is a live, 8-byte-aligned-length buffer of
        // `count` sock_filter records; the helper copies it and does not retain
        // the pointer.
        let rc = unsafe { krunc_seccomp_install(ctx.seccomp.as_ptr() as *const c_void, count) };
        if rc != 0 {
            pr_err!("krunc: seccomp install failed: {}\n", rc);
            return rc; // ctx dropped -> freed; container does not start unconfined
        }
    }

    // Sealed filesystem domain: a Landlock ruleset that permits writes/creation
    // only beneath the configured scratch paths. Like seccomp it is inherited
    // across exec and (under no_new_privs) un-relaxable for the container's life,
    // giving an immutable rootfs. -ENOSYS (a kernel without Landlock) is the only
    // tolerated failure; any other error is fatal (fail closed).
    let lrc = apply_landlock(&ctx.landlock_rw);
    if lrc != 0 && lrc != -38 {
        pr_err!("krunc: landlock seal failed: {}\n", lrc);
        return lrc; // ctx dropped -> freed; do not start a container missing its seal
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
