//! The `/dev/krunc` ioctl client — the one place `unsafe` is needed (the ioctl
//! syscall). Everything is funnelled through the small [`Device`] type.

use std::fs::{File, OpenOptions};
use std::io;
use std::os::unix::io::AsRawFd;

use krunc_abi::{DomainSpec, Op};

/// Mirrors the kernel's `#[repr(C)] KruncCmd` (32 bytes, no padding).
#[repr(C)]
#[derive(Default)]
struct KruncCmd {
    spec_ptr: u64,
    id: u64,
    spec_len: u32,
    pid: i32,
    sig: i32,
    state: u32,
}

const fn iowr(nr: u64) -> u64 {
    // _IOC(dir=READ|WRITE, type='k', nr, size=sizeof(KruncCmd)=32)
    (3u64 << 30) | (32u64 << 16) | ((b'k' as u64) << 8) | nr
}

const NR_CREATE: u64 = 1;
const NR_START: u64 = 2;
const NR_STATE: u64 = 3;
const NR_KILL: u64 = 4;
const NR_DELETE: u64 = 5;

/// Lifecycle state reported by the kernel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KState {
    /// Set up, not yet started.
    Created,
    /// Entrypoint running.
    Running,
    /// Exited.
    Stopped,
}

/// An open handle to the krunc control device.
pub struct Device {
    file: File,
}

impl Device {
    /// Open `/dev/krunc`.
    pub fn open() -> io::Result<Self> {
        let file = OpenOptions::new().read(true).write(true).open("/dev/krunc")?;
        Ok(Self { file })
    }

    fn ioctl(&self, nr: u64, cmd: &mut KruncCmd) -> io::Result<()> {
        // SAFETY: `cmd` is a valid, suitably-sized, writable `KruncCmd`; the
        // request number encodes that exact size; the fd is open for read+write.
        // The request arg type differs by libc (c_ulong on glibc, c_int on musl);
        // `as _` casts to whichever it is, preserving the 32-bit ioctl number.
        let ret = unsafe {
            libc::ioctl(self.file.as_raw_fd(), iowr(nr) as _, cmd as *mut KruncCmd)
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    /// Create a (paused) domain from `spec`. Returns `(kernel_id, host_pid)`.
    pub fn create(&self, spec: &DomainSpec) -> io::Result<(u64, i32)> {
        let blob = spec
            .encode(Op::Create)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))?;
        let mut cmd = KruncCmd {
            spec_ptr: blob.as_ptr() as u64,
            spec_len: blob.len() as u32,
            ..Default::default()
        };
        self.ioctl(NR_CREATE, &mut cmd)?;
        // `blob` is alive across the ioctl above.
        Ok((cmd.id, cmd.pid))
    }

    /// Send a raw, pre-encoded spec blob through the create ioctl. Used by the
    /// `__decode-check` self-test to drive malformed blobs straight at the
    /// kernel's binary decoder (the real untrusted boundary).
    pub fn create_raw(&self, blob: &[u8]) -> io::Result<(u64, i32)> {
        let mut cmd = KruncCmd {
            spec_ptr: blob.as_ptr() as u64,
            spec_len: blob.len() as u32,
            ..Default::default()
        };
        self.ioctl(NR_CREATE, &mut cmd)?;
        Ok((cmd.id, cmd.pid))
    }

    /// Release a created domain so its entrypoint execs.
    pub fn start(&self, id: u64) -> io::Result<()> {
        let mut cmd = KruncCmd { id, ..Default::default() };
        self.ioctl(NR_START, &mut cmd)
    }

    /// Query a domain's state and pid.
    pub fn state(&self, id: u64) -> io::Result<(KState, i32)> {
        let mut cmd = KruncCmd { id, ..Default::default() };
        self.ioctl(NR_STATE, &mut cmd)?;
        let st = match cmd.state {
            0 => KState::Created,
            1 => KState::Running,
            _ => KState::Stopped,
        };
        Ok((st, cmd.pid))
    }

    /// Signal a domain's init.
    pub fn kill(&self, id: u64, sig: i32) -> io::Result<()> {
        let mut cmd = KruncCmd { id, sig, ..Default::default() };
        self.ioctl(NR_KILL, &mut cmd)
    }

    /// Destroy a domain.
    pub fn delete(&self, id: u64) -> io::Result<()> {
        let mut cmd = KruncCmd { id, ..Default::default() };
        self.ioctl(NR_DELETE, &mut cmd)
    }
}
