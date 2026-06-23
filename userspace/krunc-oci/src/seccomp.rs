//! Compile an OCI `linux.seccomp` policy into a classic-BPF `sock_filter[]`
//! program — the wire form the kernel installs (after `no_new_privs`) to enforce
//! a sealed syscall policy for the container's whole life.
//!
//! The generated program has the canonical seccomp shape:
//!
//! ```text
//!     A = seccomp_data.arch
//!     if A != AUDIT_ARCH_X86_64: return KILL_PROCESS   // refuse foreign arch
//!     // one self-contained block per (syscall, rule):
//!     A = seccomp_data.nr
//!     if A != nr_1: goto next_block                     // wrong syscall
//!     <compare each argument matcher; mismatch -> next_block>
//!     return action_1
//!     ...
//!     return default_action
//! ```
//!
//! Only the x86-64 native ABI is targeted (the kernel krunc runs on). The
//! equality argument matchers (`SCMP_CMP_EQ`, `SCMP_CMP_MASKED_EQ`) are compiled
//! into real 64-bit BPF comparisons; the ordered and not-equal operators cannot
//! be expressed without early-exit jumps in this block scheme and are rejected
//! rather than silently dropped (see [`OciError::Unsupported`]), because the
//! runtime-spec requires applying a configured property as specified or erroring.

use crate::{OciError, Seccomp, SeccompArg};
use krunc_abi::MAX_SECCOMP;

/// `struct sock_filter` (uapi/linux/filter.h): a single classic-BPF instruction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SockFilter {
    code: u16,
    jt: u8,
    jf: u8,
    k: u32,
}

impl SockFilter {
    fn stmt(code: u16, k: u32) -> Self {
        SockFilter { code, jt: 0, jf: 0, k }
    }
    fn jump(code: u16, k: u32, jt: u8, jf: u8) -> Self {
        SockFilter { code, jt, jf, k }
    }
    /// Serialize in native (little-endian) layout, matching the kernel struct.
    fn write_to(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.code.to_le_bytes());
        out.push(self.jt);
        out.push(self.jf);
        out.extend_from_slice(&self.k.to_le_bytes());
    }
}

// classic-BPF opcodes (uapi/linux/bpf_common.h).
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_RET: u16 = 0x06;
const BPF_K: u16 = 0x00;
const BPF_ALU: u16 = 0x04;
const BPF_AND: u16 = 0x50;

const LD_W_ABS: u16 = BPF_LD | BPF_W | BPF_ABS;
const JMP_JEQ_K: u16 = BPF_JMP | BPF_JEQ | BPF_K;
const ALU_AND_K: u16 = BPF_ALU | BPF_AND | BPF_K;
const RET_K: u16 = BPF_RET | BPF_K;

// `struct seccomp_data` field offsets (uapi/linux/seccomp.h).
const SD_NR: u32 = 0;
const SD_ARCH: u32 = 4;
/// Offset of `args[0]`; each argument is a `u64` (low word first on x86-64).
const SD_ARGS: u32 = 16;

/// `AUDIT_ARCH_X86_64` (uapi/linux/audit.h): the only ABI krunc targets.
const AUDIT_ARCH_X86_64: u32 = 0xc000_003e;

// `SECCOMP_RET_*` action return values (uapi/linux/seccomp.h).
const RET_KILL_PROCESS: u32 = 0x8000_0000;
const RET_KILL_THREAD: u32 = 0x0000_0000;
const RET_TRAP: u32 = 0x0003_0000;
const RET_ERRNO: u32 = 0x0005_0000;
const RET_LOG: u32 = 0x7ffc_0000;
const RET_ALLOW: u32 = 0x7fff_0000;
const RET_ERRNO_DATA: u32 = 0x0000_ffff;

/// The kernel rejects classic-BPF programs longer than this (BPF_MAXINSNS).
const BPF_MAXINSNS: usize = 4096;

const EPERM: u32 = 1;

/// Map an OCI `SCMP_ACT_*` action (with an optional errno) to a `SECCOMP_RET_*`.
fn action_ret(action: &str, errno: Option<u32>) -> Result<u32, OciError> {
    Ok(match action {
        "SCMP_ACT_ALLOW" => RET_ALLOW,
        "SCMP_ACT_ERRNO" => RET_ERRNO | (errno.unwrap_or(EPERM) & RET_ERRNO_DATA),
        "SCMP_ACT_KILL" | "SCMP_ACT_KILL_THREAD" => RET_KILL_THREAD,
        "SCMP_ACT_KILL_PROCESS" => RET_KILL_PROCESS,
        "SCMP_ACT_TRAP" => RET_TRAP,
        "SCMP_ACT_LOG" => RET_LOG,
        // SCMP_ACT_NOTIFY / SCMP_ACT_TRACE need a supervisor/tracer; refuse
        // rather than compile a policy that does not do what was asked.
        _ => return Err(OciError::Unsupported("seccomp action")),
    })
}

/// Compile a parsed OCI seccomp policy into a serialized `sock_filter[]` blob.
///
/// Each `(syscall, rule)` becomes a self-contained block: load the syscall
/// number, compare it, then compare each configured argument matcher. Every
/// mismatch falls through to the next block; only a full match returns the
/// rule's action. Argument matchers are compiled into real BPF comparisons
/// (not silently dropped), so the installed filter enforces exactly the
/// predicate the caller asked for.
pub fn compile(s: &Seccomp) -> Result<Vec<u8>, OciError> {
    let default_ret = action_ret(&s.default_action, s.default_errno_ret)?;

    // krunc compiles syscall numbers for the x86-64 native ABI only and kills
    // foreign-architecture syscalls outright; it cannot apply per-architecture
    // rules for any other architecture, so a configured non-x86-64 architecture
    // is rejected rather than silently ignored.
    for arch in &s.architectures {
        if arch != "SCMP_ARCH_X86_64" {
            return Err(OciError::Unsupported(
                "seccomp architecture other than SCMP_ARCH_X86_64",
            ));
        }
    }

    let mut prog: Vec<SockFilter> = Vec::new();
    // Architecture guard: a foreign-ABI syscall (e.g. i386 on x86-64) bypasses
    // number-based filters, so refuse it outright.
    prog.push(SockFilter::stmt(LD_W_ABS, SD_ARCH));
    prog.push(SockFilter::jump(JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
    prog.push(SockFilter::stmt(RET_K, RET_KILL_PROCESS));

    for rule in &s.syscalls {
        let ret = action_ret(&rule.action, rule.errno_ret)?;
        // Unknown syscall names do not exist on this architecture and are
        // skipped, matching libseccomp.
        for name in &rule.names {
            if let Some(nr) = syscall_nr(name) {
                append_syscall_block(&mut prog, nr, &rule.args, ret)?;
            }
        }
    }
    prog.push(SockFilter::stmt(RET_K, default_ret));

    if prog.len() > BPF_MAXINSNS {
        return Err(OciError::Unsupported("seccomp program too large"));
    }
    let mut bytes = Vec::with_capacity(prog.len() * 8);
    for insn in &prog {
        insn.write_to(&mut bytes);
    }
    if bytes.len() > MAX_SECCOMP {
        return Err(OciError::Unsupported("seccomp program exceeds ABI limit"));
    }
    Ok(bytes)
}

/// Append a block matching syscall `nr` with every matcher in `args` satisfied
/// (matchers are ANDed, as in the OCI spec); the block returns `ret` on a full
/// match and otherwise falls through to whatever follows it.
fn append_syscall_block(
    prog: &mut Vec<SockFilter>,
    nr: u32,
    args: &[SeccompArg],
    ret: u32,
) -> Result<(), OciError> {
    // Indices of jump instructions whose "fail" edge must target the end of the
    // block (the first instruction after this block's terminating RET).
    let mut fails: Vec<(usize, bool)> = Vec::new();
    prog.push(SockFilter::stmt(LD_W_ABS, SD_NR));
    prog.push(SockFilter::jump(JMP_JEQ_K, nr, 0, 0));
    fails.push((prog.len() - 1, false));
    for a in args {
        emit_arg_eq(prog, &mut fails, a)?;
    }
    prog.push(SockFilter::stmt(RET_K, ret));
    let end = prog.len();
    for (idx, is_jt) in fails {
        let off = end - idx - 1;
        if off > u8::MAX as usize {
            return Err(OciError::Unsupported("seccomp argument block too large"));
        }
        if is_jt {
            prog[idx].jt = off as u8;
        } else {
            prog[idx].jf = off as u8;
        }
    }
    Ok(())
}

/// Emit one equality argument matcher, comparing the 64-bit syscall argument as
/// two 32-bit halves. `SCMP_CMP_EQ` requires both halves to equal `value`;
/// `SCMP_CMP_MASKED_EQ` requires `(arg & valueTwo) == value` per half. Each
/// failing comparison records a jump to the end of the enclosing block. Ordered
/// and not-equal operators are rejected rather than mis-compiled.
fn emit_arg_eq(
    prog: &mut Vec<SockFilter>,
    fails: &mut Vec<(usize, bool)>,
    a: &SeccompArg,
) -> Result<(), OciError> {
    if a.index > 5 {
        return Err(OciError::Unsupported("seccomp argument index out of range"));
    }
    let off = SD_ARGS + a.index * 8;
    let vlo = (a.value & 0xffff_ffff) as u32;
    let vhi = (a.value >> 32) as u32;
    match a.op.as_str() {
        "SCMP_CMP_EQ" => {
            prog.push(SockFilter::stmt(LD_W_ABS, off));
            prog.push(SockFilter::jump(JMP_JEQ_K, vlo, 0, 0));
            fails.push((prog.len() - 1, false));
            prog.push(SockFilter::stmt(LD_W_ABS, off + 4));
            prog.push(SockFilter::jump(JMP_JEQ_K, vhi, 0, 0));
            fails.push((prog.len() - 1, false));
        }
        "SCMP_CMP_MASKED_EQ" => {
            let mlo = (a.value_two & 0xffff_ffff) as u32;
            let mhi = (a.value_two >> 32) as u32;
            prog.push(SockFilter::stmt(LD_W_ABS, off));
            prog.push(SockFilter::stmt(ALU_AND_K, mlo));
            prog.push(SockFilter::jump(JMP_JEQ_K, vlo, 0, 0));
            fails.push((prog.len() - 1, false));
            prog.push(SockFilter::stmt(LD_W_ABS, off + 4));
            prog.push(SockFilter::stmt(ALU_AND_K, mhi));
            prog.push(SockFilter::jump(JMP_JEQ_K, vhi, 0, 0));
            fails.push((prog.len() - 1, false));
        }
        _ => {
            return Err(OciError::Unsupported(
                "seccomp argument operator (only SCMP_CMP_EQ and SCMP_CMP_MASKED_EQ)",
            ))
        }
    }
    Ok(())
}

/// x86-64 syscall name → number (`arch/x86/entry/syscalls/syscall_64.tbl`,
/// `common` + `64` ABIs). Names absent here are treated as "not on this arch".
fn syscall_nr(name: &str) -> Option<u32> {
    let nr: u32 = match name {
        "read" => 0,
        "write" => 1,
        "open" => 2,
        "close" => 3,
        "stat" => 4,
        "fstat" => 5,
        "lstat" => 6,
        "poll" => 7,
        "lseek" => 8,
        "mmap" => 9,
        "mprotect" => 10,
        "munmap" => 11,
        "brk" => 12,
        "rt_sigaction" => 13,
        "rt_sigprocmask" => 14,
        "rt_sigreturn" => 15,
        "ioctl" => 16,
        "pread64" => 17,
        "pwrite64" => 18,
        "readv" => 19,
        "writev" => 20,
        "access" => 21,
        "pipe" => 22,
        "select" => 23,
        "sched_yield" => 24,
        "mremap" => 25,
        "msync" => 26,
        "mincore" => 27,
        "madvise" => 28,
        "shmget" => 29,
        "shmat" => 30,
        "shmctl" => 31,
        "dup" => 32,
        "dup2" => 33,
        "pause" => 34,
        "nanosleep" => 35,
        "getitimer" => 36,
        "alarm" => 37,
        "setitimer" => 38,
        "getpid" => 39,
        "sendfile" => 40,
        "socket" => 41,
        "connect" => 42,
        "accept" => 43,
        "sendto" => 44,
        "recvfrom" => 45,
        "sendmsg" => 46,
        "recvmsg" => 47,
        "shutdown" => 48,
        "bind" => 49,
        "listen" => 50,
        "getsockname" => 51,
        "getpeername" => 52,
        "socketpair" => 53,
        "setsockopt" => 54,
        "getsockopt" => 55,
        "clone" => 56,
        "fork" => 57,
        "vfork" => 58,
        "execve" => 59,
        "exit" => 60,
        "wait4" => 61,
        "kill" => 62,
        "uname" => 63,
        "semget" => 64,
        "semop" => 65,
        "semctl" => 66,
        "shmdt" => 67,
        "msgget" => 68,
        "msgsnd" => 69,
        "msgrcv" => 70,
        "msgctl" => 71,
        "fcntl" => 72,
        "flock" => 73,
        "fsync" => 74,
        "fdatasync" => 75,
        "truncate" => 76,
        "ftruncate" => 77,
        "getdents" => 78,
        "getcwd" => 79,
        "chdir" => 80,
        "fchdir" => 81,
        "rename" => 82,
        "mkdir" => 83,
        "rmdir" => 84,
        "creat" => 85,
        "link" => 86,
        "unlink" => 87,
        "symlink" => 88,
        "readlink" => 89,
        "chmod" => 90,
        "fchmod" => 91,
        "chown" => 92,
        "fchown" => 93,
        "lchown" => 94,
        "umask" => 95,
        "gettimeofday" => 96,
        "getrlimit" => 97,
        "getrusage" => 98,
        "sysinfo" => 99,
        "times" => 100,
        "ptrace" => 101,
        "getuid" => 102,
        "syslog" => 103,
        "getgid" => 104,
        "setuid" => 105,
        "setgid" => 106,
        "geteuid" => 107,
        "getegid" => 108,
        "setpgid" => 109,
        "getppid" => 110,
        "getpgrp" => 111,
        "setsid" => 112,
        "setreuid" => 113,
        "setregid" => 114,
        "getgroups" => 115,
        "setgroups" => 116,
        "setresuid" => 117,
        "getresuid" => 118,
        "setresgid" => 119,
        "getresgid" => 120,
        "getpgid" => 121,
        "setfsuid" => 122,
        "setfsgid" => 123,
        "getsid" => 124,
        "capget" => 125,
        "capset" => 126,
        "rt_sigpending" => 127,
        "rt_sigtimedwait" => 128,
        "rt_sigqueueinfo" => 129,
        "rt_sigsuspend" => 130,
        "sigaltstack" => 131,
        "utime" => 132,
        "mknod" => 133,
        "uselib" => 134,
        "personality" => 135,
        "ustat" => 136,
        "statfs" => 137,
        "fstatfs" => 138,
        "sysfs" => 139,
        "getpriority" => 140,
        "setpriority" => 141,
        "sched_setparam" => 142,
        "sched_getparam" => 143,
        "sched_setscheduler" => 144,
        "sched_getscheduler" => 145,
        "sched_get_priority_max" => 146,
        "sched_get_priority_min" => 147,
        "sched_rr_get_interval" => 148,
        "mlock" => 149,
        "munlock" => 150,
        "mlockall" => 151,
        "munlockall" => 152,
        "vhangup" => 153,
        "modify_ldt" => 154,
        "pivot_root" => 155,
        "_sysctl" => 156,
        "prctl" => 157,
        "arch_prctl" => 158,
        "adjtimex" => 159,
        "setrlimit" => 160,
        "chroot" => 161,
        "sync" => 162,
        "acct" => 163,
        "settimeofday" => 164,
        "mount" => 165,
        "umount2" => 166,
        "swapon" => 167,
        "swapoff" => 168,
        "reboot" => 169,
        "sethostname" => 170,
        "setdomainname" => 171,
        "iopl" => 172,
        "ioperm" => 173,
        "create_module" => 174,
        "init_module" => 175,
        "delete_module" => 176,
        "get_kernel_syms" => 177,
        "query_module" => 178,
        "quotactl" => 179,
        "nfsservctl" => 180,
        "getpmsg" => 181,
        "putpmsg" => 182,
        "afs_syscall" => 183,
        "tuxcall" => 184,
        "security" => 185,
        "gettid" => 186,
        "readahead" => 187,
        "setxattr" => 188,
        "lsetxattr" => 189,
        "fsetxattr" => 190,
        "getxattr" => 191,
        "lgetxattr" => 192,
        "fgetxattr" => 193,
        "listxattr" => 194,
        "llistxattr" => 195,
        "flistxattr" => 196,
        "removexattr" => 197,
        "lremovexattr" => 198,
        "fremovexattr" => 199,
        "tkill" => 200,
        "time" => 201,
        "futex" => 202,
        "sched_setaffinity" => 203,
        "sched_getaffinity" => 204,
        "set_thread_area" => 205,
        "io_setup" => 206,
        "io_destroy" => 207,
        "io_getevents" => 208,
        "io_submit" => 209,
        "io_cancel" => 210,
        "get_thread_area" => 211,
        "lookup_dcookie" => 212,
        "epoll_create" => 213,
        "epoll_ctl_old" => 214,
        "epoll_wait_old" => 215,
        "remap_file_pages" => 216,
        "getdents64" => 217,
        "set_tid_address" => 218,
        "restart_syscall" => 219,
        "semtimedop" => 220,
        "fadvise64" => 221,
        "timer_create" => 222,
        "timer_settime" => 223,
        "timer_gettime" => 224,
        "timer_getoverrun" => 225,
        "timer_delete" => 226,
        "clock_settime" => 227,
        "clock_gettime" => 228,
        "clock_getres" => 229,
        "clock_nanosleep" => 230,
        "exit_group" => 231,
        "epoll_wait" => 232,
        "epoll_ctl" => 233,
        "tgkill" => 234,
        "utimes" => 235,
        "vserver" => 236,
        "mbind" => 237,
        "set_mempolicy" => 238,
        "get_mempolicy" => 239,
        "mq_open" => 240,
        "mq_unlink" => 241,
        "mq_timedsend" => 242,
        "mq_timedreceive" => 243,
        "mq_notify" => 244,
        "mq_getsetattr" => 245,
        "kexec_load" => 246,
        "waitid" => 247,
        "add_key" => 248,
        "request_key" => 249,
        "keyctl" => 250,
        "ioprio_set" => 251,
        "ioprio_get" => 252,
        "inotify_init" => 253,
        "inotify_add_watch" => 254,
        "inotify_rm_watch" => 255,
        "migrate_pages" => 256,
        "openat" => 257,
        "mkdirat" => 258,
        "mknodat" => 259,
        "fchownat" => 260,
        "futimesat" => 261,
        "newfstatat" => 262,
        "unlinkat" => 263,
        "renameat" => 264,
        "linkat" => 265,
        "symlinkat" => 266,
        "readlinkat" => 267,
        "fchmodat" => 268,
        "faccessat" => 269,
        "pselect6" => 270,
        "ppoll" => 271,
        "unshare" => 272,
        "set_robust_list" => 273,
        "get_robust_list" => 274,
        "splice" => 275,
        "tee" => 276,
        "sync_file_range" => 277,
        "vmsplice" => 278,
        "move_pages" => 279,
        "utimensat" => 280,
        "epoll_pwait" => 281,
        "signalfd" => 282,
        "timerfd_create" => 283,
        "eventfd" => 284,
        "fallocate" => 285,
        "timerfd_settime" => 286,
        "timerfd_gettime" => 287,
        "accept4" => 288,
        "signalfd4" => 289,
        "eventfd2" => 290,
        "epoll_create1" => 291,
        "dup3" => 292,
        "pipe2" => 293,
        "inotify_init1" => 294,
        "preadv" => 295,
        "pwritev" => 296,
        "rt_tgsigqueueinfo" => 297,
        "perf_event_open" => 298,
        "recvmmsg" => 299,
        "fanotify_init" => 300,
        "fanotify_mark" => 301,
        "prlimit64" => 302,
        "name_to_handle_at" => 303,
        "open_by_handle_at" => 304,
        "clock_adjtime" => 305,
        "syncfs" => 306,
        "sendmmsg" => 307,
        "setns" => 308,
        "getcpu" => 309,
        "process_vm_readv" => 310,
        "process_vm_writev" => 311,
        "kcmp" => 312,
        "finit_module" => 313,
        "sched_setattr" => 314,
        "sched_getattr" => 315,
        "renameat2" => 316,
        "seccomp" => 317,
        "getrandom" => 318,
        "memfd_create" => 319,
        "kexec_file_load" => 320,
        "bpf" => 321,
        "execveat" => 322,
        "userfaultfd" => 323,
        "membarrier" => 324,
        "mlock2" => 325,
        "copy_file_range" => 326,
        "preadv2" => 327,
        "pwritev2" => 328,
        "pkey_mprotect" => 329,
        "pkey_alloc" => 330,
        "pkey_free" => 331,
        "statx" => 332,
        "io_pgetevents" => 333,
        "rseq" => 334,
        "uretprobe" => 335,
        "uprobe" => 336,
        "pidfd_send_signal" => 424,
        "io_uring_setup" => 425,
        "io_uring_enter" => 426,
        "io_uring_register" => 427,
        "open_tree" => 428,
        "move_mount" => 429,
        "fsopen" => 430,
        "fsconfig" => 431,
        "fsmount" => 432,
        "fspick" => 433,
        "pidfd_open" => 434,
        "clone3" => 435,
        "close_range" => 436,
        "openat2" => 437,
        "pidfd_getfd" => 438,
        "faccessat2" => 439,
        "process_madvise" => 440,
        "epoll_pwait2" => 441,
        "mount_setattr" => 442,
        "quotactl_fd" => 443,
        "landlock_create_ruleset" => 444,
        "landlock_add_rule" => 445,
        "landlock_restrict_self" => 446,
        "memfd_secret" => 447,
        "process_mrelease" => 448,
        "futex_waitv" => 449,
        "set_mempolicy_home_node" => 450,
        "cachestat" => 451,
        "fchmodat2" => 452,
        "map_shadow_stack" => 453,
        "futex_wake" => 454,
        "futex_wait" => 455,
        "futex_requeue" => 456,
        "statmount" => 457,
        "listmount" => 458,
        "lsm_get_self_attr" => 459,
        "lsm_set_self_attr" => 460,
        "lsm_list_modules" => 461,
        "mseal" => 462,
        "setxattrat" => 463,
        "getxattrat" => 464,
        "listxattrat" => 465,
        "removexattrat" => 466,
        "open_tree_attr" => 467,
        "file_getattr" => 468,
        "file_setattr" => 469,
        _ => return None,
    };
    Some(nr)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Seccomp, SeccompSyscall};

    fn decode(bytes: &[u8]) -> Vec<SockFilter> {
        assert_eq!(bytes.len() % 8, 0, "blob must be a whole number of insns");
        bytes
            .chunks_exact(8)
            .map(|c| SockFilter {
                code: u16::from_le_bytes([c[0], c[1]]),
                jt: c[2],
                jf: c[3],
                k: u32::from_le_bytes([c[4], c[5], c[6], c[7]]),
            })
            .collect()
    }

    #[test]
    fn default_allow_with_errno_blocklist() {
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["chmod".into(), "fchmodat".into()],
                action: "SCMP_ACT_ERRNO".into(),
                errno_ret: Some(1),
                args: vec![],
            }],
        };
        let prog = decode(&compile(&s).unwrap());

        // Header: load arch, branch, kill foreign.
        assert_eq!(prog[0], SockFilter::stmt(LD_W_ABS, SD_ARCH));
        assert_eq!(prog[1], SockFilter::jump(JMP_JEQ_K, AUDIT_ARCH_X86_64, 1, 0));
        assert_eq!(prog[2], SockFilter::stmt(RET_K, RET_KILL_PROCESS));
        // chmod(90) block: load nr, match, ERRNO(EPERM); mismatch falls through.
        assert_eq!(prog[3], SockFilter::stmt(LD_W_ABS, SD_NR));
        assert_eq!(prog[4], SockFilter::jump(JMP_JEQ_K, 90, 0, 1));
        assert_eq!(prog[5], SockFilter::stmt(RET_K, RET_ERRNO | 1));
        // fchmodat(268) block.
        assert_eq!(prog[6], SockFilter::stmt(LD_W_ABS, SD_NR));
        assert_eq!(prog[7], SockFilter::jump(JMP_JEQ_K, 268, 0, 1));
        assert_eq!(prog[8], SockFilter::stmt(RET_K, RET_ERRNO | 1));
        // Default allow.
        assert_eq!(prog[9], SockFilter::stmt(RET_K, RET_ALLOW));
        assert_eq!(prog.len(), 10);
    }

    #[test]
    fn unknown_syscalls_are_skipped() {
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["not_a_syscall".into(), "kill".into()],
                action: "SCMP_ACT_KILL_PROCESS".into(),
                errno_ret: None,
                args: vec![],
            }],
        };
        let prog = decode(&compile(&s).unwrap());
        // Only kill(62) survives -> header(4) + 1 rule(2) + default(1).
        assert_eq!(prog.len(), 7);
        assert_eq!(prog[4], SockFilter::jump(JMP_JEQ_K, 62, 0, 1));
        assert_eq!(prog[5], SockFilter::stmt(RET_K, RET_KILL_PROCESS));
    }

    #[test]
    fn unsupported_arg_op_rejected() {
        // EQ and MASKED_EQ compile to real comparisons; ordered/not-equal
        // operators cannot be expressed in the block scheme without early-exit
        // jumps, so per the runtime-spec they are rejected rather than dropped.
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["ioctl".into()],
                action: "SCMP_ACT_ERRNO".into(),
                errno_ret: None,
                args: vec![SeccompArg {
                    index: 1,
                    value: 0,
                    value_two: 0,
                    op: "SCMP_CMP_LT".into(),
                }],
            }],
        };
        assert!(matches!(compile(&s), Err(OciError::Unsupported(_))));
    }

    #[test]
    fn unknown_action_rejected() {
        let s = Seccomp {
            default_action: "SCMP_ACT_NOTIFY".into(),
            ..Default::default()
        };
        assert!(matches!(compile(&s), Err(OciError::Unsupported(_))));
    }

    #[test]
    fn nonnative_architecture_rejected() {
        // krunc handles only x86-64 syscall numbers; a config requesting rules for
        // another architecture cannot be applied as specified, so it is rejected.
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec!["SCMP_ARCH_X86_64".into(), "SCMP_ARCH_X86".into()],
            syscalls: vec![],
        };
        assert!(matches!(compile(&s), Err(OciError::Unsupported(_))));
        // The native architecture alone is accepted.
        let ok = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec!["SCMP_ARCH_X86_64".into()],
            syscalls: vec![],
        };
        assert!(compile(&ok).is_ok());
    }

    /// A minimal classic-BPF interpreter for the opcode subset this compiler
    /// emits, used to prove generated filters return the intended action.
    fn run_bpf(prog: &[SockFilter], data: &[u8]) -> u32 {
        let mut a: u32 = 0;
        let mut pc: usize = 0;
        loop {
            let insn = prog[pc];
            if insn.code == LD_W_ABS {
                let o = insn.k as usize;
                a = u32::from_le_bytes([data[o], data[o + 1], data[o + 2], data[o + 3]]);
                pc += 1;
            } else if insn.code == ALU_AND_K {
                a &= insn.k;
                pc += 1;
            } else if insn.code == JMP_JEQ_K {
                let take = if a == insn.k { insn.jt } else { insn.jf } as usize;
                pc += 1 + take;
            } else if insn.code == RET_K {
                return insn.k;
            } else {
                panic!("interpreter: unhandled opcode {:#06x}", insn.code);
            }
        }
    }

    fn seccomp_data(nr: u32, arch: u32, args: [u64; 6]) -> Vec<u8> {
        let mut d = Vec::with_capacity(64);
        d.extend_from_slice(&nr.to_le_bytes());
        d.extend_from_slice(&arch.to_le_bytes());
        d.extend_from_slice(&0u64.to_le_bytes()); // instruction_pointer
        for a in args {
            d.extend_from_slice(&a.to_le_bytes());
        }
        d
    }

    #[test]
    fn eq_arg_matcher_compiles_and_runs() {
        // ioctl(fd, TCGETS=0x5401, ...) -> ERRNO(EPERM); other ioctls allowed.
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["ioctl".into()],
                action: "SCMP_ACT_ERRNO".into(),
                errno_ret: Some(1),
                args: vec![SeccompArg {
                    index: 1,
                    value: 0x5401,
                    value_two: 0,
                    op: "SCMP_CMP_EQ".into(),
                }],
            }],
        };
        let prog = decode(&compile(&s).unwrap());

        // Matching syscall + matching arg -> ERRNO(EPERM).
        let hit = seccomp_data(16, AUDIT_ARCH_X86_64, [3, 0x5401, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &hit), RET_ERRNO | 1);
        // Right syscall, wrong arg -> falls through to default ALLOW.
        let wrong_arg = seccomp_data(16, AUDIT_ARCH_X86_64, [3, 0x1234, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &wrong_arg), RET_ALLOW);
        // Different syscall with the same arg value -> ALLOW.
        let other_call = seccomp_data(0, AUDIT_ARCH_X86_64, [3, 0x5401, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &other_call), RET_ALLOW);
        // Foreign architecture -> killed regardless of arguments.
        let foreign = seccomp_data(16, 0x4000_0003, [3, 0x5401, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &foreign), RET_KILL_PROCESS);
    }

    #[test]
    fn eq_arg_matcher_checks_high_word() {
        // A value above 2^32 must compare both 32-bit halves, not just the low
        // one, otherwise the filter would match on a truncated argument.
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["read".into()],
                action: "SCMP_ACT_KILL_PROCESS".into(),
                errno_ret: None,
                args: vec![SeccompArg {
                    index: 0,
                    value: 0x1_0000_0002,
                    value_two: 0,
                    op: "SCMP_CMP_EQ".into(),
                }],
            }],
        };
        let prog = decode(&compile(&s).unwrap());

        let exact = seccomp_data(0, AUDIT_ARCH_X86_64, [0x1_0000_0002, 0, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &exact), RET_KILL_PROCESS);
        // Same low word, zero high word -> must NOT match.
        let low_only = seccomp_data(0, AUDIT_ARCH_X86_64, [0x0000_0002, 0, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &low_only), RET_ALLOW);
    }

    #[test]
    fn masked_eq_arg_matcher_runs() {
        // clone with CLONE_NEWUSER-style masked bit set -> ERRNO; mirrors how the
        // moby/containerd default profile gates clone flags.
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["clone".into()],
                action: "SCMP_ACT_ERRNO".into(),
                errno_ret: Some(22),
                args: vec![SeccompArg {
                    index: 0,
                    value: 0x10,
                    value_two: 0xff,
                    op: "SCMP_CMP_MASKED_EQ".into(),
                }],
            }],
        };
        let prog = decode(&compile(&s).unwrap());

        // (0x110 & 0xff) == 0x10 -> match.
        let masked_hit = seccomp_data(56, AUDIT_ARCH_X86_64, [0x110, 0, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &masked_hit), RET_ERRNO | 22);
        // (0x120 & 0xff) == 0x20 != 0x10 -> no match.
        let masked_miss = seccomp_data(56, AUDIT_ARCH_X86_64, [0x120, 0, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &masked_miss), RET_ALLOW);
    }

    #[test]
    fn multiple_arg_matchers_are_anded() {
        // Both predicates must hold for the rule to fire (OCI ANDs a rule's args).
        let s = Seccomp {
            default_action: "SCMP_ACT_ALLOW".into(),
            default_errno_ret: None,
            architectures: vec![],
            syscalls: vec![SeccompSyscall {
                names: vec!["socket".into()],
                action: "SCMP_ACT_ERRNO".into(),
                errno_ret: Some(1),
                args: vec![
                    SeccompArg {
                        index: 0,
                        value: 2,
                        value_two: 0,
                        op: "SCMP_CMP_EQ".into(),
                    },
                    SeccompArg {
                        index: 1,
                        value: 1,
                        value_two: 0,
                        op: "SCMP_CMP_EQ".into(),
                    },
                ],
            }],
        };
        let prog = decode(&compile(&s).unwrap());

        let both = seccomp_data(41, AUDIT_ARCH_X86_64, [2, 1, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &both), RET_ERRNO | 1);
        // First matches, second does not -> no match.
        let only_first = seccomp_data(41, AUDIT_ARCH_X86_64, [2, 9, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &only_first), RET_ALLOW);
        // Second matches, first does not -> no match.
        let only_second = seccomp_data(41, AUDIT_ARCH_X86_64, [9, 1, 0, 0, 0, 0]);
        assert_eq!(run_bpf(&prog, &only_second), RET_ALLOW);
    }

    fn sm64(s: &mut u64) -> u64 {
        *s = s.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = *s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Fuzz the compiler with random policies. Every program it accepts is loaded
    /// into the kernel, so it MUST be a well-formed classic-BPF filter: all jumps
    /// in bounds, only known opcodes, and it always terminates at a `RET`. We
    /// prove this by interpreting each accepted program over arbitrary
    /// `seccomp_data` — the interpreter indexes `prog[pc]` (an out-of-bounds jump
    /// panics) and `pc` strictly increases (so a missing terminator runs off the
    /// end and panics). A clean return for every input means the program is sound.
    #[test]
    fn compiled_seccomp_filters_are_well_formed() {
        let names = [
            "read", "write", "ioctl", "clone", "socket", "chmod", "kill", "openat", "mmap",
            "ptrace", "not_a_real_syscall",
        ];
        let actions = [
            "SCMP_ACT_ALLOW", "SCMP_ACT_ERRNO", "SCMP_ACT_KILL_PROCESS", "SCMP_ACT_KILL",
            "SCMP_ACT_LOG", "SCMP_ACT_TRAP", "SCMP_ACT_NOTIFY",
        ];
        let ops = [
            "SCMP_CMP_EQ", "SCMP_CMP_MASKED_EQ", "SCMP_CMP_NE", "SCMP_CMP_LT", "SCMP_CMP_GE",
            "bogus_op",
        ];
        let arches = ["SCMP_ARCH_X86_64", "SCMP_ARCH_X86", "SCMP_ARCH_AARCH64"];

        let mut state = 0x5EED_1234_ABCD_0001u64;
        for _ in 0..3_000 {
            let n_rules = (sm64(&mut state) % 6) as usize;
            let mut syscalls = Vec::new();
            for _ in 0..n_rules {
                let n_names = (sm64(&mut state) % 4) as usize + 1;
                let rnames = (0..n_names)
                    .map(|_| names[sm64(&mut state) as usize % names.len()].to_string())
                    .collect();
                let n_args = (sm64(&mut state) % 3) as usize;
                let args = (0..n_args)
                    .map(|_| SeccompArg {
                        index: (sm64(&mut state) % 8) as u32, // includes out-of-range (>5)
                        value: sm64(&mut state),
                        value_two: sm64(&mut state),
                        op: ops[sm64(&mut state) as usize % ops.len()].to_string(),
                    })
                    .collect();
                syscalls.push(SeccompSyscall {
                    names: rnames,
                    action: actions[sm64(&mut state) as usize % actions.len()].to_string(),
                    errno_ret: if sm64(&mut state) & 1 == 0 {
                        Some((sm64(&mut state) % 4096) as u32)
                    } else {
                        None
                    },
                    args,
                });
            }
            let n_arch = (sm64(&mut state) % 3) as usize;
            let architectures = (0..n_arch)
                .map(|_| arches[sm64(&mut state) as usize % arches.len()].to_string())
                .collect();
            let s = Seccomp {
                default_action: actions[sm64(&mut state) as usize % actions.len()].to_string(),
                default_errno_ret: None,
                architectures,
                syscalls,
            };
            if let Ok(bytes) = compile(&s) {
                assert_eq!(bytes.len() % 8, 0, "program is not a whole number of instructions");
                let prog = decode(&bytes);
                assert!(!prog.is_empty() && prog.len() <= BPF_MAXINSNS, "bad program length");
                for _ in 0..16 {
                    let arch = if sm64(&mut state) & 1 == 0 {
                        AUDIT_ARCH_X86_64
                    } else {
                        sm64(&mut state) as u32
                    };
                    let data = seccomp_data(
                        sm64(&mut state) as u32,
                        arch,
                        [
                            sm64(&mut state),
                            sm64(&mut state),
                            sm64(&mut state),
                            sm64(&mut state),
                            sm64(&mut state),
                            sm64(&mut state),
                        ],
                    );
                    let _ret = run_bpf(&prog, &data); // panics if the program is malformed
                }
            }
        }
    }
}
