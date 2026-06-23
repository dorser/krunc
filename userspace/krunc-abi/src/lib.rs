//! `krunc-abi` — the versioned, bounds-checked binary spec that crosses the
//! krunc userspace ↔ kernel boundary.
//!
//! Untrusted parsing (OCI `config.json`) happens in userspace; the kernel must
//! never parse JSON. Instead, userspace compiles a [`DomainSpec`] and encodes it
//! with [`DomainSpec::encode`] into a flat, length-prefixed, little-endian byte
//! buffer. The kernel mirrors [`decode`] with the *same* strict bounds-checking,
//! so a malformed or oversized buffer is rejected before any field is used.
//!
//! The format is a fixed header followed by tagged, length-prefixed sections
//! (TLV). Every length and count is bounded by a `MAX_*` constant; decoding is
//! total (it returns [`AbiError`] rather than panicking) and performs no
//! allocation proportional to an unvalidated length.
//!
//! This crate is `#![forbid(unsafe_code)]`: the ABI is defined in safe Rust on
//! both sides; the kernel module mirrors this logic (also without `unsafe` for
//! the parse itself).

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::fmt;

/// Magic at the start of every encoded spec: `b"KRNC"`.
pub const MAGIC: [u8; 4] = *b"KRNC";
/// ABI version understood by this crate. The kernel rejects any other value.
pub const ABI_VERSION: u32 = 1;

/// Maximum size of a whole encoded spec (defends the single `copy_from_user`).
pub const MAX_SPEC: usize = 256 * 1024;
/// Maximum length of a single string field (path, hostname, arg, env entry).
pub const MAX_STR: usize = 4096;
/// Maximum number of argv entries.
pub const MAX_ARGV: usize = 1024;
/// Maximum number of env entries.
pub const MAX_ENV: usize = 1024;
/// Maximum number of id-map entries.
pub const MAX_MAPS: usize = 340;

/// Maximum number of masked or read-only path entries.
pub const MAX_PATHS: usize = 256;

/// Maximum number of rlimit entries (there are ~16 `RLIMIT_*` resources).
pub const MAX_RLIMITS: usize = 32;

/// Maximum number of mount entries.
pub const MAX_MOUNTS: usize = 64;

// ---- clone(2) namespace flags (uapi/linux/sched.h) ----
/// `CLONE_NEWNS` — mount namespace.
pub const NS_MOUNT: u32 = 0x0002_0000;
/// `CLONE_NEWUTS` — UTS namespace.
pub const NS_UTS: u32 = 0x0400_0000;
/// `CLONE_NEWIPC` — IPC namespace.
pub const NS_IPC: u32 = 0x0800_0000;
/// `CLONE_NEWUSER` — user namespace.
pub const NS_USER: u32 = 0x1000_0000;
/// `CLONE_NEWPID` — PID namespace.
pub const NS_PID: u32 = 0x2000_0000;
/// `CLONE_NEWNET` — network namespace.
pub const NS_NET: u32 = 0x4000_0000;
/// `CLONE_NEWCGROUP` — cgroup namespace.
pub const NS_CGROUP: u32 = 0x0200_0000;

/// The set of namespaces a standard container isolates.
pub const NS_DEFAULT: u32 = NS_MOUNT | NS_UTS | NS_IPC | NS_PID | NS_NET;

// ---- boolean option flags (the `Flags` section, a u64 bitset) ----
/// Set `no_new_privs` on the domain before exec.
pub const OPT_NO_NEW_PRIVS: u64 = 1 << 0;
/// Make the rootfs read-only.
pub const OPT_ROOTFS_RO: u64 = 1 << 1;

/// The lifecycle operation a request carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum Op {
    /// Create a domain + container, paused before exec.
    Create = 1,
    /// Release a created domain so its entrypoint execs.
    Start = 2,
    /// Query a domain's state.
    State = 3,
    /// Signal a domain's init.
    Kill = 4,
    /// Destroy a domain.
    Delete = 5,
}

impl Op {
    fn from_u32(v: u32) -> Result<Self, AbiError> {
        Ok(match v {
            1 => Op::Create,
            2 => Op::Start,
            3 => Op::State,
            4 => Op::Kill,
            5 => Op::Delete,
            other => return Err(AbiError::BadOp(other)),
        })
    }
}

/// A uid/gid mapping line (`containerID hostID size`), as in `linux.uidMappings`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdMap {
    /// First id inside the container.
    pub container_id: u32,
    /// First id on the host.
    pub host_id: u32,
    /// Number of ids mapped.
    pub size: u32,
}

/// A resource limit (`setrlimit(2)`), as in `process.rlimits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rlimit {
    /// `RLIMIT_*` resource number (Linux ABI value, e.g. `RLIMIT_NOFILE = 7`).
    pub resource: u32,
    /// Soft limit.
    pub soft: u64,
    /// Hard limit.
    pub hard: u64,
}

/// A mount the kernel performs inside the container, as in `linux` `mounts[]`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Mount {
    /// Mountpoint inside the container (e.g. `/proc`, `/tmp`).
    pub destination: String,
    /// Filesystem type (e.g. `proc`, `sysfs`, `tmpfs`) or empty for a bind.
    pub fs_type: String,
    /// Source (device, fs name, or bind source path).
    pub source: String,
    /// `MS_*` mount flags precomputed from the OCI options.
    pub flags: u64,
}

/// The decoded domain specification.
///
/// This is the userspace-friendly owned form. [`encode`](DomainSpec::encode)
/// turns it into the wire format; [`decode`] reconstructs it with validation.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DomainSpec {
    /// Absolute host path of the container rootfs.
    pub rootfs: String,
    /// Container hostname (UTS namespace nodename). Empty = default.
    pub hostname: String,
    /// argv; `argv[0]` is the binary to exec.
    pub argv: Vec<String>,
    /// Environment, each `KEY=VALUE`.
    pub env: Vec<String>,
    /// Namespaces to create (bitmask of `NS_*`).
    pub namespaces: u32,
    /// uid mappings (for a user namespace).
    pub uid_maps: Vec<IdMap>,
    /// gid mappings (for a user namespace).
    pub gid_maps: Vec<IdMap>,
    /// Boolean options (`OPT_*`).
    pub flags: u64,
    /// Whether the capability sets below were explicitly specified and must be
    /// applied. When `true`, all five sets are applied *exactly* (an all-empty
    /// set therefore drops every capability — the correct, fully-confined
    /// result); when `false`, the task's capability state is left untouched
    /// (used by callers, like the raw text interface, that do not manage caps).
    pub caps_present: bool,
    /// Capability bounding set kept (a Linux capability bitmask). The bounding
    /// set is the irreversible ceiling; the other four sets are applied as-is.
    pub cap_bounding: u64,
    /// Effective capability set (active capabilities).
    pub cap_effective: u64,
    /// Permitted capability set (capabilities that may be made effective).
    pub cap_permitted: u64,
    /// Inheritable capability set (preserved across `execve`).
    pub cap_inheritable: u64,
    /// Ambient capability set (inherited by unprivileged `execve`).
    pub cap_ambient: u64,
    /// Paths made inaccessible inside the container (over-mounted so reads see
    /// nothing and writes are inert). Enforced for the container's whole life by
    /// its mount namespace.
    pub masked_paths: Vec<String>,
    /// Paths remounted read-only inside the container. Enforced for life.
    pub readonly_paths: Vec<String>,
    /// Resource limits (`setrlimit`) to apply before exec.
    pub rlimits: Vec<Rlimit>,
    /// OOM score adjustment (`/proc/self/oom_score_adj`); `None` = leave default.
    pub oom_score_adj: Option<i32>,
    /// Target uid the container process runs as (`process.user.uid`; 0 = root).
    pub uid: u32,
    /// Target gid the container process runs as (`process.user.gid`; 0 = root).
    pub gid: u32,
    /// Mounts to perform inside the container, in order (empty = no mounts).
    pub mounts: Vec<Mount>,
}

// Section tags. Stable wire identifiers; never reuse a value.
mod tag {
    pub const ROOTFS: u16 = 1;
    pub const HOSTNAME: u16 = 2;
    pub const ARGV: u16 = 3;
    pub const ENV: u16 = 4;
    pub const NAMESPACES: u16 = 5;
    pub const UID_MAPS: u16 = 6;
    pub const GID_MAPS: u16 = 7;
    pub const FLAGS: u16 = 8;
    pub const CAP_BOUNDING: u16 = 9;
    pub const MASKED_PATHS: u16 = 11;
    pub const RO_PATHS: u16 = 12;
    pub const RLIMITS: u16 = 13;
    pub const OOM_SCORE_ADJ: u16 = 14;
    pub const CAP_SETS: u16 = 15;
    pub const USER: u16 = 16;
    pub const MOUNTS: u16 = 17;
    // 10 (seccomp) and 18 (landlock) retired — never reuse.
}

/// Errors from encoding or (strict) decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AbiError {
    /// Buffer does not start with [`MAGIC`].
    BadMagic,
    /// `abi_version` is not [`ABI_VERSION`].
    UnsupportedVersion(u32),
    /// `op` field is not a known [`Op`].
    BadOp(u32),
    /// Buffer ended before a field was fully read.
    Truncated,
    /// A length/count exceeded its `MAX_*` bound.
    TooLarge {
        /// What was being read.
        what: &'static str,
        /// The offending value.
        value: usize,
        /// The limit.
        limit: usize,
    },
    /// A section tag appeared more than once.
    Duplicate(u16),
    /// A required section was absent for the given op.
    Missing(&'static str),
    /// A string field was not valid UTF-8.
    Utf8,
    /// Trailing bytes remained after the declared sections.
    TrailingBytes,
}

impl fmt::Display for AbiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbiError::BadMagic => write!(f, "bad magic"),
            AbiError::UnsupportedVersion(v) => write!(f, "unsupported abi version {v}"),
            AbiError::BadOp(v) => write!(f, "invalid op {v}"),
            AbiError::Truncated => write!(f, "truncated buffer"),
            AbiError::TooLarge { what, value, limit } => {
                write!(f, "{what} too large: {value} > {limit}")
            }
            AbiError::Duplicate(t) => write!(f, "duplicate section tag {t}"),
            AbiError::Missing(s) => write!(f, "missing required section {s}"),
            AbiError::Utf8 => write!(f, "invalid utf-8 in string field"),
            AbiError::TrailingBytes => write!(f, "trailing bytes after sections"),
        }
    }
}

impl std::error::Error for AbiError {}

// ============================ encoding ============================

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }
    fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }
    fn bytes(&mut self, b: &[u8]) {
        self.buf.extend_from_slice(b);
    }
    /// Write a section header `[tag][pad][len]` then the payload built by `body`.
    fn section(&mut self, tag: u16, body: impl FnOnce(&mut Writer)) {
        let mut inner = Writer::new();
        body(&mut inner);
        self.u16(tag);
        self.u16(0); // reserved/pad (keeps payload 4-aligned start)
        self.u32(inner.buf.len() as u32);
        self.bytes(&inner.buf);
    }
}

fn write_strvec(w: &mut Writer, items: &[String]) {
    w.u32(items.len() as u32);
    for s in items {
        w.u32(s.len() as u32);
        w.bytes(s.as_bytes());
    }
}

fn write_str(w: &mut Writer, s: &str) {
    w.u32(s.len() as u32);
    w.bytes(s.as_bytes());
}

fn write_mounts(w: &mut Writer, mounts: &[Mount]) {
    w.u32(mounts.len() as u32);
    for m in mounts {
        write_str(w, &m.destination);
        write_str(w, &m.fs_type);
        write_str(w, &m.source);
        w.u64(m.flags);
    }
}

fn write_maps(w: &mut Writer, maps: &[IdMap]) {
    w.u32(maps.len() as u32);
    for m in maps {
        w.u32(m.container_id);
        w.u32(m.host_id);
        w.u32(m.size);
    }
}

fn write_rlimits(w: &mut Writer, limits: &[Rlimit]) {
    w.u32(limits.len() as u32);
    for l in limits {
        w.u32(l.resource);
        w.u64(l.soft);
        w.u64(l.hard);
    }
}

impl DomainSpec {
    /// Validate sizes against the `MAX_*` bounds (the same bounds the decoder
    /// enforces) before encoding, so we never produce a buffer the kernel would
    /// reject.
    pub fn validate(&self) -> Result<(), AbiError> {
        check_len("rootfs", self.rootfs.len(), MAX_STR)?;
        check_len("hostname", self.hostname.len(), MAX_STR)?;
        check_len("argv", self.argv.len(), MAX_ARGV)?;
        for a in &self.argv {
            check_len("arg", a.len(), MAX_STR)?;
        }
        check_len("env", self.env.len(), MAX_ENV)?;
        for e in &self.env {
            check_len("env-entry", e.len(), MAX_STR)?;
        }
        check_len("uid_maps", self.uid_maps.len(), MAX_MAPS)?;
        check_len("gid_maps", self.gid_maps.len(), MAX_MAPS)?;
        check_len("masked_paths", self.masked_paths.len(), MAX_PATHS)?;
        check_len("readonly_paths", self.readonly_paths.len(), MAX_PATHS)?;
        check_len("rlimits", self.rlimits.len(), MAX_RLIMITS)?;
        check_len("mounts", self.mounts.len(), MAX_MOUNTS)?;
        Ok(())
    }

    /// Encode `self` for operation `op` into the wire format.
    pub fn encode(&self, op: Op) -> Result<Vec<u8>, AbiError> {
        self.validate()?;
        let mut w = Writer::new();
        w.bytes(&MAGIC);
        w.u32(ABI_VERSION);
        w.u32(op as u32);

        // sections (only emit the non-default ones)
        let mut count: u32 = 0;
        let mut body = Writer::new();
        let mut emit = |tag: u16, f: &mut dyn FnMut(&mut Writer)| {
            body.section(tag, |w| f(w));
            count += 1;
        };

        if !self.rootfs.is_empty() {
            emit(tag::ROOTFS, &mut |w| w.bytes(self.rootfs.as_bytes()));
        }
        if !self.hostname.is_empty() {
            emit(tag::HOSTNAME, &mut |w| w.bytes(self.hostname.as_bytes()));
        }
        if !self.argv.is_empty() {
            emit(tag::ARGV, &mut |w| write_strvec(w, &self.argv));
        }
        if !self.env.is_empty() {
            emit(tag::ENV, &mut |w| write_strvec(w, &self.env));
        }
        if self.namespaces != 0 {
            emit(tag::NAMESPACES, &mut |w| w.u32(self.namespaces));
        }
        if !self.uid_maps.is_empty() {
            emit(tag::UID_MAPS, &mut |w| write_maps(w, &self.uid_maps));
        }
        if !self.gid_maps.is_empty() {
            emit(tag::GID_MAPS, &mut |w| write_maps(w, &self.gid_maps));
        }
        if self.flags != 0 {
            emit(tag::FLAGS, &mut |w| w.u64(self.flags));
        }
        if self.caps_present {
            emit(tag::CAP_BOUNDING, &mut |w| w.u64(self.cap_bounding));
            emit(tag::CAP_SETS, &mut |w| {
                w.u64(self.cap_effective);
                w.u64(self.cap_permitted);
                w.u64(self.cap_inheritable);
                w.u64(self.cap_ambient);
            });
        }
        if !self.masked_paths.is_empty() {
            emit(tag::MASKED_PATHS, &mut |w| write_strvec(w, &self.masked_paths));
        }
        if !self.readonly_paths.is_empty() {
            emit(tag::RO_PATHS, &mut |w| write_strvec(w, &self.readonly_paths));
        }
        if !self.rlimits.is_empty() {
            emit(tag::RLIMITS, &mut |w| write_rlimits(w, &self.rlimits));
        }
        if let Some(adj) = self.oom_score_adj {
            emit(tag::OOM_SCORE_ADJ, &mut |w| w.u32(adj as u32));
        }
        if self.uid != 0 || self.gid != 0 {
            emit(tag::USER, &mut |w| {
                w.u32(self.uid);
                w.u32(self.gid);
            });
        }
        if !self.mounts.is_empty() {
            emit(tag::MOUNTS, &mut |w| write_mounts(w, &self.mounts));
        }

        w.u32(count);
        w.bytes(&body.buf);

        if w.buf.len() > MAX_SPEC {
            return Err(AbiError::TooLarge {
                what: "spec",
                value: w.buf.len(),
                limit: MAX_SPEC,
            });
        }
        Ok(w.buf)
    }
}

fn check_len(what: &'static str, value: usize, limit: usize) -> Result<(), AbiError> {
    if value > limit {
        Err(AbiError::TooLarge { what, value, limit })
    } else {
        Ok(())
    }
}

// ============================ decoding ============================

/// A bounds-checked, panic-free cursor over the input buffer.
struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn take(&mut self, n: usize) -> Result<&'a [u8], AbiError> {
        if n > self.remaining() {
            return Err(AbiError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
    fn u16(&mut self) -> Result<u16, AbiError> {
        Ok(u16::from_le_bytes(self.take(2)?.try_into().unwrap()))
    }
    fn u32(&mut self) -> Result<u32, AbiError> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn u64(&mut self) -> Result<u64, AbiError> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().unwrap()))
    }
}

fn read_string(r: &mut Reader<'_>, what: &'static str, limit: usize) -> Result<String, AbiError> {
    let len = r.u32()? as usize;
    check_len(what, len, limit)?;
    let bytes = r.take(len)?;
    String::from_utf8(bytes.to_vec()).map_err(|_| AbiError::Utf8)
}

fn read_strvec(r: &mut Reader<'_>, what: &'static str, max: usize) -> Result<Vec<String>, AbiError> {
    let n = r.u32()? as usize;
    check_len(what, n, max)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(read_string(r, "string", MAX_STR)?);
    }
    Ok(v)
}

fn read_maps(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<IdMap>, AbiError> {
    let n = r.u32()? as usize;
    check_len(what, n, MAX_MAPS)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(IdMap {
            container_id: r.u32()?,
            host_id: r.u32()?,
            size: r.u32()?,
        });
    }
    Ok(v)
}

fn read_rlimits(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<Rlimit>, AbiError> {
    let n = r.u32()? as usize;
    check_len(what, n, MAX_RLIMITS)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(Rlimit {
            resource: r.u32()?,
            soft: r.u64()?,
            hard: r.u64()?,
        });
    }
    Ok(v)
}

fn read_mounts(r: &mut Reader<'_>, what: &'static str) -> Result<Vec<Mount>, AbiError> {
    let n = r.u32()? as usize;
    check_len(what, n, MAX_MOUNTS)?;
    let mut v = Vec::with_capacity(n);
    for _ in 0..n {
        v.push(Mount {
            destination: read_string(r, "mount.destination", MAX_STR)?,
            fs_type: read_string(r, "mount.type", MAX_STR)?,
            source: read_string(r, "mount.source", MAX_STR)?,
            flags: r.u64()?,
        });
    }
    Ok(v)
}

/// Decode a buffer into `(op, spec)`, enforcing every bound. Total: never panics.
pub fn decode(buf: &[u8]) -> Result<(Op, DomainSpec), AbiError> {
    if buf.len() > MAX_SPEC {
        return Err(AbiError::TooLarge {
            what: "spec",
            value: buf.len(),
            limit: MAX_SPEC,
        });
    }
    let mut r = Reader::new(buf);
    if r.take(4)? != MAGIC {
        return Err(AbiError::BadMagic);
    }
    let version = r.u32()?;
    if version != ABI_VERSION {
        return Err(AbiError::UnsupportedVersion(version));
    }
    let op = Op::from_u32(r.u32()?)?;
    let section_count = r.u32()? as usize;
    // A section header is 8 bytes; a buffer can't claim more sections than fit.
    check_len("section_count", section_count, MAX_SPEC / 8)?;

    let mut spec = DomainSpec::default();
    let mut seen: u64 = 0; // bitset of tags already parsed
    for _ in 0..section_count {
        let t = r.u16()?;
        let _pad = r.u16()?;
        let len = r.u32()? as usize;
        if len > r.remaining() {
            return Err(AbiError::Truncated);
        }
        let payload = r.take(len)?;
        if t < 64 {
            let bit = 1u64 << t;
            if seen & bit != 0 {
                return Err(AbiError::Duplicate(t));
            }
            seen |= bit;
        }
        let mut sr = Reader::new(payload);
        match t {
            tag::ROOTFS => spec.rootfs = utf8(payload, MAX_STR, "rootfs")?,
            tag::HOSTNAME => spec.hostname = utf8(payload, MAX_STR, "hostname")?,
            tag::ARGV => spec.argv = read_strvec(&mut sr, "argv", MAX_ARGV)?,
            tag::ENV => spec.env = read_strvec(&mut sr, "env", MAX_ENV)?,
            tag::NAMESPACES => spec.namespaces = sr.u32()?,
            tag::UID_MAPS => spec.uid_maps = read_maps(&mut sr, "uid_maps")?,
            tag::GID_MAPS => spec.gid_maps = read_maps(&mut sr, "gid_maps")?,
            tag::FLAGS => spec.flags = sr.u64()?,
            tag::CAP_BOUNDING => {
                spec.caps_present = true;
                spec.cap_bounding = sr.u64()?;
            }
            tag::CAP_SETS => {
                spec.cap_effective = sr.u64()?;
                spec.cap_permitted = sr.u64()?;
                spec.cap_inheritable = sr.u64()?;
                spec.cap_ambient = sr.u64()?;
            }
            tag::MASKED_PATHS => {
                spec.masked_paths = read_strvec(&mut sr, "masked_paths", MAX_PATHS)?;
            }
            tag::RO_PATHS => {
                spec.readonly_paths = read_strvec(&mut sr, "readonly_paths", MAX_PATHS)?;
            }
            tag::RLIMITS => {
                spec.rlimits = read_rlimits(&mut sr, "rlimits")?;
            }
            tag::OOM_SCORE_ADJ => {
                spec.oom_score_adj = Some(sr.u32()? as i32);
            }
            tag::USER => {
                spec.uid = sr.u32()?;
                spec.gid = sr.u32()?;
            }
            tag::MOUNTS => {
                spec.mounts = read_mounts(&mut sr, "mounts")?;
            }
            _ => { /* unknown tag: ignore for forward-compat */ }
        }
    }
    if r.remaining() != 0 {
        return Err(AbiError::TrailingBytes);
    }

    if op == Op::Create {
        if spec.rootfs.is_empty() {
            return Err(AbiError::Missing("rootfs"));
        }
        if spec.argv.is_empty() {
            return Err(AbiError::Missing("argv"));
        }
    }
    Ok((op, spec))
}

fn utf8(b: &[u8], limit: usize, what: &'static str) -> Result<String, AbiError> {
    check_len(what, b.len(), limit)?;
    String::from_utf8(b.to_vec()).map_err(|_| AbiError::Utf8)
}

// ============================ tests ============================

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> DomainSpec {
        DomainSpec {
            rootfs: "/containers/demo/rootfs".into(),
            hostname: "oci-demo".into(),
            argv: vec!["/bin/sh".into(), "/init.sh".into()],
            env: vec!["PATH=/bin".into(), "TERM=linux".into()],
            namespaces: NS_DEFAULT | NS_USER,
            uid_maps: vec![IdMap { container_id: 0, host_id: 100000, size: 65536 }],
            gid_maps: vec![IdMap { container_id: 0, host_id: 100000, size: 65536 }],
            flags: OPT_NO_NEW_PRIVS | OPT_ROOTFS_RO,
            caps_present: true,
            cap_bounding: 0x0000_0000_a80c_25fb,
            cap_effective: 0x0000_0000_0000_0001,
            cap_permitted: 0x0000_0000_a80c_25fb,
            cap_inheritable: 0,
            cap_ambient: 0,
            masked_paths: vec!["/proc/kcore".into(), "/proc/sysrq-trigger".into()],
            readonly_paths: vec!["/proc/sys".into(), "/bin".into()],
            rlimits: vec![
                Rlimit { resource: 7, soft: 1024, hard: 4096 },
                Rlimit { resource: 4, soft: 0, hard: 0 },
            ],
            oom_score_adj: Some(-500),
            uid: 65534,
            gid: 65534,
            mounts: vec![
                Mount {
                    destination: "/proc".into(),
                    fs_type: "proc".into(),
                    source: "proc".into(),
                    flags: 0,
                },
                Mount {
                    destination: "/tmp".into(),
                    fs_type: "tmpfs".into(),
                    source: "tmpfs".into(),
                    flags: 0x0000_000e, // MS_NOSUID|MS_NODEV|MS_NOEXEC
                },
            ],
        }
    }

    #[test]
    fn round_trip_full() {
        let s = sample();
        let buf = s.encode(Op::Create).unwrap();
        let (op, decoded) = decode(&buf).unwrap();
        assert_eq!(op, Op::Create);
        assert_eq!(decoded, s);
    }

    #[test]
    fn round_trip_minimal() {
        let s = DomainSpec {
            rootfs: "/r".into(),
            argv: vec!["/bin/true".into()],
            namespaces: NS_DEFAULT,
            ..Default::default()
        };
        let buf = s.encode(Op::Create).unwrap();
        let (_op, d) = decode(&buf).unwrap();
        assert_eq!(d, s);
    }

    #[test]
    fn all_ops_round_trip() {
        for op in [Op::Create, Op::Start, Op::State, Op::Kill, Op::Delete] {
            // Start/State/Kill/Delete don't require rootfs/argv.
            let s = if op == Op::Create { sample() } else { DomainSpec::default() };
            let buf = s.encode(op).unwrap();
            let (got, _d) = decode(&buf).unwrap();
            assert_eq!(got, op);
        }
    }

    #[test]
    fn rejects_bad_magic() {
        let mut buf = sample().encode(Op::Create).unwrap();
        buf[0] ^= 0xff;
        assert_eq!(decode(&buf), Err(AbiError::BadMagic));
    }

    #[test]
    fn rejects_bad_version() {
        let mut buf = sample().encode(Op::Create).unwrap();
        buf[4] = 0xff; // bump version low byte
        assert!(matches!(decode(&buf), Err(AbiError::UnsupportedVersion(_))));
    }

    #[test]
    fn rejects_bad_op() {
        let mut buf = sample().encode(Op::Create).unwrap();
        // op is at offset 8..12
        buf[8] = 99;
        assert!(matches!(decode(&buf), Err(AbiError::BadOp(_))));
    }

    #[test]
    fn rejects_every_truncation() {
        let buf = sample().encode(Op::Create).unwrap();
        for n in 0..buf.len() {
            // Every strict prefix must be rejected, never panic, never accepted.
            assert!(decode(&buf[..n]).is_err(), "prefix len {n} was accepted");
        }
    }

    #[test]
    fn rejects_create_without_rootfs() {
        let s = DomainSpec {
            argv: vec!["/bin/true".into()],
            ..Default::default()
        };
        assert_eq!(s.encode(Op::Create).and_then(|b| decode(&b).map(|_| ())), Err(AbiError::Missing("rootfs")));
    }

    #[test]
    fn rejects_create_without_argv() {
        let s = DomainSpec { rootfs: "/r".into(), ..Default::default() };
        assert_eq!(decode(&s.encode(Op::Create).unwrap()), Err(AbiError::Missing("argv")));
    }

    #[test]
    fn validate_rejects_oversized_argv() {
        let s = DomainSpec {
            rootfs: "/r".into(),
            argv: vec!["x".into(); MAX_ARGV + 1],
            ..Default::default()
        };
        assert!(matches!(s.encode(Op::Create), Err(AbiError::TooLarge { .. })));
    }

    #[test]
    fn validate_rejects_oversized_string() {
        let s = DomainSpec {
            rootfs: "x".repeat(MAX_STR + 1),
            argv: vec!["/bin/true".into()],
            ..Default::default()
        };
        assert!(matches!(s.encode(Op::Create), Err(AbiError::TooLarge { .. })));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut buf = sample().encode(Op::Create).unwrap();
        buf.push(0);
        assert_eq!(decode(&buf), Err(AbiError::TrailingBytes));
    }

    #[test]
    fn unknown_tag_ignored_forward_compat() {
        // Hand-craft a buffer with one unknown high tag plus the required ones.
        let mut w = Writer::new();
        w.bytes(&MAGIC);
        w.u32(ABI_VERSION);
        w.u32(Op::Create as u32);
        w.u32(3); // rootfs, argv, unknown
        let mut body = Writer::new();
        body.section(tag::ROOTFS, |w| w.bytes(b"/r"));
        body.section(tag::ARGV, |w| write_strvec(w, &["/bin/true".to_string()]));
        body.section(0xfff0, |w| w.bytes(b"future")); // unknown, must be ignored
        w.u32(3);
        // Note: count already written above; rebuild cleanly instead.
        let mut w2 = Writer::new();
        w2.bytes(&MAGIC);
        w2.u32(ABI_VERSION);
        w2.u32(Op::Create as u32);
        w2.u32(3);
        w2.bytes(&body.buf);
        let (_op, d) = decode(&w2.buf).unwrap();
        assert_eq!(d.rootfs, "/r");
        assert_eq!(d.argv, vec!["/bin/true".to_string()]);
    }

    /// The decoder runs on untrusted bytes from userspace; in the kernel a panic
    /// is fatal. This deterministically fuzzes `decode` with random buffers and
    /// hostile mutations of a valid one (length/count fields set to huge values),
    /// asserting it always returns a `Result` — never panics, over/under-reads,
    /// or over-allocates. The PRNG is seeded so any failure reproduces.
    #[test]
    fn decode_never_panics_on_arbitrary_input() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        // splitmix64 PRNG (deterministic, no external dependency).
        let mut state: u64 = 0x1234_5678_9ABC_DEF0;
        let mut next = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let try_decode = |buf: &[u8]| {
            catch_unwind(AssertUnwindSafe(|| {
                let _ = decode(buf);
            }))
        };

        // 1. Purely random buffers of varying length.
        for _ in 0..30_000 {
            let len = (next() % 1500) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            assert!(try_decode(&buf).is_ok(), "panicked on random buffer {buf:?}");
        }

        let valid = sample().encode(Op::Create).unwrap();

        // 2. A valid header (MAGIC+version+op) followed by random section bytes,
        //    so the fuzzer exercises the section/tag loop and its sub-readers.
        let header = valid[..12].to_vec();
        for _ in 0..30_000 {
            let mut buf = header.clone();
            let extra = (next() % 300) as usize;
            buf.extend((0..extra).map(|_| (next() & 0xff) as u8));
            assert!(try_decode(&buf).is_ok(), "panicked on header+random {buf:?}");
        }

        // 3. Single-byte mutations at every position of a valid buffer.
        for pos in 0..valid.len() {
            for delta in [0x01u8, 0x3f, 0x80, 0xff] {
                let mut buf = valid.clone();
                buf[pos] ^= delta;
                assert!(try_decode(&buf).is_ok(), "panicked on mutation pos={pos} delta={delta:#x}");
            }
        }

        // 4. Overwrite each 4-byte window with u32::MAX (hostile length/count
        //    fields) — the classic decoder over-read / over-allocate trap.
        for pos in 0..valid.len().saturating_sub(4) {
            let mut buf = valid.clone();
            buf[pos..pos + 4].copy_from_slice(&u32::MAX.to_le_bytes());
            assert!(try_decode(&buf).is_ok(), "panicked on u32::MAX at pos={pos}");
        }
    }

    fn sm64(s: &mut u64) -> u64 {
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn rand_str(s: &mut u64, maxlen: usize) -> String {
        let n = (sm64(s) as usize % maxlen) + 1;
        (0..n).map(|_| ((sm64(s) % 26) as u8 + b'a') as char).collect()
    }

    fn rand_strvec(s: &mut u64, maxn: usize, maxlen: usize) -> Vec<String> {
        let n = sm64(s) as usize % (maxn + 1);
        (0..n).map(|_| rand_str(s, maxlen)).collect()
    }

    /// Encoding then decoding a canonical, in-bounds spec must reproduce it
    /// exactly, across randomized field values and edge cases (absent optionals,
    /// negative `oom_score_adj` round-tripped through `u32`, large bitmasks). This
    /// guards against an asymmetry between the encoder and decoder (a field
    /// written but not read back, or vice versa).
    #[test]
    fn encode_decode_round_trips_random_specs() {
        let mut state: u64 = 0xCAFE_F00D_1234_5678;
        for _ in 0..5_000 {
            let caps_present = sm64(&mut state) & 1 == 0;
            let oom = if sm64(&mut state) & 1 == 0 {
                Some(sm64(&mut state) as i32) // exercises negative values via u32
            } else {
                None
            };
            let n_maps = sm64(&mut state) as usize % 3;
            let n_rl = sm64(&mut state) as usize % 3;
            let n_mounts = sm64(&mut state) as usize % 3;
            let spec = DomainSpec {
                rootfs: rand_str(&mut state, 24), // required + non-empty for Create
                hostname: if sm64(&mut state) & 1 == 0 { rand_str(&mut state, 16) } else { String::new() },
                argv: {
                    // required: at least one arg.
                    let mut a = vec![rand_str(&mut state, 16)];
                    a.extend(rand_strvec(&mut state, 3, 16));
                    a
                },
                env: rand_strvec(&mut state, 4, 16),
                namespaces: sm64(&mut state) as u32,
                uid_maps: (0..n_maps)
                    .map(|_| IdMap {
                        container_id: sm64(&mut state) as u32,
                        host_id: sm64(&mut state) as u32,
                        size: sm64(&mut state) as u32,
                    })
                    .collect(),
                gid_maps: (0..n_maps)
                    .map(|_| IdMap {
                        container_id: sm64(&mut state) as u32,
                        host_id: sm64(&mut state) as u32,
                        size: sm64(&mut state) as u32,
                    })
                    .collect(),
                flags: sm64(&mut state),
                caps_present,
                cap_bounding: if caps_present { sm64(&mut state) } else { 0 },
                cap_effective: if caps_present { sm64(&mut state) } else { 0 },
                cap_permitted: if caps_present { sm64(&mut state) } else { 0 },
                cap_inheritable: if caps_present { sm64(&mut state) } else { 0 },
                cap_ambient: if caps_present { sm64(&mut state) } else { 0 },
                masked_paths: rand_strvec(&mut state, 4, 16),
                readonly_paths: rand_strvec(&mut state, 4, 16),
                rlimits: (0..n_rl)
                    .map(|_| Rlimit {
                        resource: sm64(&mut state) as u32 % 16,
                        soft: sm64(&mut state),
                        hard: sm64(&mut state),
                    })
                    .collect(),
                oom_score_adj: oom,
                uid: sm64(&mut state) as u32,
                gid: sm64(&mut state) as u32,
                mounts: (0..n_mounts)
                    .map(|_| Mount {
                        destination: rand_str(&mut state, 16),
                        fs_type: rand_str(&mut state, 8),
                        source: rand_str(&mut state, 16),
                        flags: sm64(&mut state),
                    })
                    .collect(),
            };
            let buf = spec.encode(Op::Create).expect("canonical in-bounds spec must encode");
            let (op, decoded) = decode(&buf).expect("must decode what we encoded");
            assert_eq!(op, Op::Create);
            assert_eq!(decoded, spec, "encode/decode round-trip mismatch");
        }
    }
}
