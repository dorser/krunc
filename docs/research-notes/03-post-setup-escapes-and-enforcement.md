Agent completed. agent_id: runtime-escape-research, agent_type: research, status: completed, description: Research post-setup container escapes + in-kernel enforcement, elapsed: 632s, total_turns: 0, duration: 569s

Now I have all the evidence I need. Here is the comprehensive, fully-cited research report.

---

# Post-Setup Linux Container Escapes & Continuous Kernel Confinement for `krunc`

**Context.** `krunc` is a proof-of-concept Rust kernel module that performs container orchestration entirely inside the kernel: `user_mode_thread()` + `container_entry()` + `kernel_execve()`. The README and `docs/DESIGN.md` §9 already identify *"no seccomp, no capability dropping, no user-namespace uid/gid mapping"* as the first class of next steps. This report underpins exactly those next steps, but extends the question: how does krunc keep a container contained for its **entire lifetime**, not just at setup?

---

## Part A — Post-Setup Escape Classes (Container Already Running)

### A.1 Kernel-Vulnerability Escapes via Allowed Syscalls

The fundamental threat: every syscall the container is allowed to make is an entry point into a potentially buggy kernel subsystem. Here is a taxonomy of the most important examples.

#### A.1.1 Dirty COW — CVE-2016-5195

**Root cause.** A race condition in the copy-on-write (COW) path of the memory-mapped file handling code. An attacker opens a read-only file with `mmap(MAP_PRIVATE)`, then races `write()` through `/proc/self/mem` (or `ptrace(PTRACE_POKEDATA)`) with `madvise(MADV_DONTNEED)`. The `MADV_DONTNEED` causes the page to be dropped and re-faulted, racing the dirty-bit check and allowing a write to reach the underlying (read-only) page cache. Fix: `git commit 19be0eaff...` (Oct 2016). CVSS: AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H. CVE-2016-5195, CISA KEV. [NVD CVE-2016-5195](https://nvd.nist.gov/vuln/detail/CVE-2016-5195)

**How a running container hits it.** The `ptrace` path only needs `ptrace()`, `mmap()`, `madvise()`, and `open()` — all commonly allowed. The `/proc/self/mem` path only needs `open()` + `write()`.

**What seccomp blocking removes.** Block `ptrace(2)` and `process_vm_writev(2)` to remove the PTRACE_POKEDATA path. Block `madvise(2)` with `MADV_DONTNEED` (or filter the advice argument). Either blocks the race.

gVisor's architecture guide explicitly cites Dirty COW as the canonical example of the syscall API attack vector: *"for Dirty Cow, an application would open a specific file in /proc or use a specific ptrace system call, and use multiple threads in order to trigger a race condition when touching a fresh page of memory."* [gVisor Security](https://gvisor.dev/docs/architecture_guide/security/)

#### A.1.2 Dirty Pipe — CVE-2022-0847

**Root cause.** Introduced in Linux 5.8, present through 5.16.10/5.15.24. The `copy_page_to_iter_pipe()` and `push_pipe()` helper functions failed to initialize the `flags` field of a new `pipe_buffer`. This left stale flags from the previous user, including `PIPE_BUF_FLAG_CAN_MERGE`. When a `splice()` fills a pipe and the merge flag is set, a subsequent `write()` to the pipe can write *into the page cache of a previously spliced read-only file*, bypassing DAC and read-only mounts. CM4all engineer Max Kellermann discovered it in `/var/log/auth.log` writes corrupting a read-only binary. Fix: Linux 5.16.11, 5.15.25, 5.10.102. CVE-2022-0847, CISA KEV, CVSS High. [NVD CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847); [dirtypipe.cm4all.com](https://dirtypipe.cm4all.com/)

**Entry points.** `splice(2)`, `pipe(2)`, `write(2)`. The splice path is the critical one.

**seccomp surface reduction.** Blocking `splice(2)` removes the entry point entirely. This is a meaningful reduction: splice is a rarely-needed syscall for most container workloads. The kernel documentation explicitly notes that seccomp *"is meant to be a tool for sandbox developers to use"* and that BPF filters cannot TOCTOU-race since they operate on register values, not memory pointers. [kernel.org/doc/html/latest/userspace-api/seccomp_filter.html]

#### A.1.3 OverlayFS Privilege Escalation — CVE-2021-3493

**Root cause.** Ubuntu-specific kernel patch that allowed OverlayFS to be mounted inside unprivileged user namespaces, combined with a bug in how OverlayFS handled extended attribute (xattr) writes. A user could `unshare(CLONE_NEWUSER | CLONE_NEWNS)` to gain effective capabilities inside a user namespace, then mount an OverlayFS with a lower layer containing a SUID-root binary, exploit the xattr miscopy to gain real `CAP_SYS_ADMIN` on the host. CVE-2021-3493, CISA KEV, CVSS AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H. Fix: Linux kernel commit `7c03e2cda4a584cadc398e8f6641ca9988a39d52`. [NVD CVE-2021-3493](https://nvd.nist.gov/vuln/detail/CVE-2021-3493); [Ubuntu USN-4917-1](https://ubuntu.com/security/notices/USN-4917-1)

**Entry points.** `unshare(CLONE_NEWUSER)` or `clone(CLONE_NEWUSER)`, `mount()` (for OverlayFS).

**seccomp surface reduction.** Blocking `clone(CLONE_NEWUSER)` and `unshare(CLONE_NEWUSER)` removes this entire class. These flags are rarely needed inside an already-isolated container and are a long-standing source of privilege escalation vectors.

#### A.1.4 nf_tables Use-After-Free — CVE-2022-32250

**Root cause.** A use-after-free in the Linux Netfilter `nf_tables` subsystem. The `nft_verdict_init()` function allowed positive values as drop errors within the hook verdict. When `nf_hook_slow()` called these hooks, positive return values caused a double-free of the `nf_hook_ops` structure, leading to UAF. Exploited to gain LPE. Published by Theori; PoC at `github.com/theori-io/CVE-2022-32250-exploit`. Fix: `git commit 520778042ccca...` (June 2022). CVE-2022-32250, CVSS 7.8. Affected: Linux 4.1–5.18.1. [NVD CVE-2022-32250](https://nvd.nist.gov/vuln/detail/CVE-2022-32250)

**Entry points.** `socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER)` to communicate with the nftables subsystem.

**seccomp surface reduction.** Blocking `socket(AF_NETLINK, ...)` removes the nftables, iproute2, and iptables interfaces entirely from the container. Most application containers have no legitimate need for netlink sockets.

#### A.1.5 StackRot — CVE-2023-3269

**Root cause.** A use-after-free in the Linux memory management subsystem, introduced when Linux 6.1 changed VMA (virtual memory area) locking from mmap_lock to per-VMA locks. A race condition in the lock acquisition path between `expand_stack()` and `find_vma()` allowed a UAF on VMA objects. CVE-2023-3269 explicitly lists *"escalate containers"* as an attack outcome. Affected: Linux 6.1–6.4. Fix: Linux 6.4.1. [NVD CVE-2023-3269](https://nvd.nist.gov/vuln/detail/CVE-2023-3269)

**Entry points.** Standard `mmap(2)`, `mremap(2)`, stack expansion (page fault handler).

**seccomp surface reduction.** This is an example where pure syscall blocking is difficult (mmap cannot be blocked for most applications). Defense-in-depth requires combining seccomp with other controls (Landlock, capability stripping, kernel version pinning).

#### A.1.6 nf_tables Double-Free — CVE-2024-1086

**Root cause.** Another nf_tables UAF: `nft_verdict_init()` allows positive values as drop errors within hook verdicts; `nf_hook_slow()` causes a double-free when `NF_DROP` is issued with a drop error resembling `NF_ACCEPT`. Fix: `git commit f342de4e2f33e0e39165d8639387aa6c19dff660`. Affected: Linux 3.15–6.7. CISA KEV (active exploitation). Pwning.tech writeup at `pwning.tech/nftables/`; PoC at `github.com/Notselwyn/CVE-2024-1086`. [NVD CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086)

**Entry points.** Same as CVE-2022-32250: netlink socket to nftables.

**seccomp surface reduction.** Blocking `socket(AF_NETLINK)` removes both CVE-2022-32250 and CVE-2024-1086 simultaneously.

#### A.1.7 io_uring Bugs

**Root cause pattern.** `io_uring` (introduced Linux 5.1) exposes a large, complex kernel code surface via a ring-buffer shared between userspace and kernel. Multiple UAF, OOB-read/write, and privilege escalation CVEs have been found (CVE-2022-29582: use-after-free in `io_uring`; CVE-2022-2585: use-after-free in POSIX timer teardown via io_uring; etc.). The attack surface is enormous: the ring setup maps kernel memory to userspace, and the submission/completion queue processing handles dozens of operation types.

**seccomp surface reduction.** Blocking `io_uring_setup(2)` (syscall NR 425 on x86-64) prevents the container from creating any io_uring context, eliminating this entire attack surface. This is strongly recommended for all containers that do not explicitly require io_uring. Google's Container-Optimized OS and various hardened Kubernetes runtimes block io_uring by default.

#### A.1.8 eBPF Verifier Bugs

**Root cause pattern.** The eBPF verifier is a complex program (100K+ lines) that must prove program safety. Multiple CVEs document bypasses: CVE-2021-3489 (ring buffer OOB), CVE-2021-31440 (bounds checking bypass), CVE-2021-29155 (pointer arithmetic leading to arbitrary kernel read), and others. An attacker inside a container who can call `bpf(BPF_PROG_LOAD, ...)` with a crafted program can bypass the verifier and gain kernel-mode code execution.

**seccomp surface reduction.** Blocking the `bpf(2)` syscall entirely removes this attack surface for container workloads that do not need eBPF. This also prevents the container from loading BPF-LSM programs that might attempt to countermand the host's policy.

---

### A.2 Misconfig / Capability Abuse at Runtime

#### A.2.1 cgroup v1 `release_agent` Escape

**Mechanism.** cgroup v1's `notify_on_release` mechanism runs the file path specified in `release_agent` (root-owned, host-wide path) as root whenever the last task leaves a cgroup. Felix Wilhelm (Google P0, 2019) demonstrated that a container with `CAP_SYS_ADMIN` and a writable cgroupfs can:
1. Mount the host's cgroupfs (or create a new cgroup hierarchy): `mount("none", "/tmp/cgrp", "cgroup", 0, NULL)`
2. Set `notify_on_release=1` on a child cgroup
3. Write a host-visible path (e.g., a shell script in a shared volume) to `release_agent`
4. Run a process in the child cgroup and kill it
5. The kernel runs `release_agent` as root on the *host*, achieving a full container escape

See `kernel.org/doc/html/latest/admin-guide/cgroup-v1/cgroups.html` §1.4 for `notify_on_release` documentation. The `release_agent` file *"exists in the top cgroup only"* and is called by the kernel as the specified program.

**Continuous enforcement stops it.** seccomp blocking `mount(2)` prevents the cgroupfs mounting step. The LSM hook `security_sb_mount` is called before any filesystem mount — an LSM can check whether the caller is in a container namespace and deny cgroupfs mounts. `CAP_SYS_ADMIN` removal makes the mount step impossible regardless.

#### A.2.2 CAP_SYS_ADMIN Omnipotence

`CAP_SYS_ADMIN` is documented as *"Note: this capability is overloaded"* in `capabilities(7)`. [man7.org/linux/man-pages/man7/capabilities.7.html]. It grants ~50 different kernel operations including: all filesystem mounts, `clone(CLONE_NEWUSER)`, `setns()`, keyctl privileged operations, `syslog()`, `vm86()`, BPF privileged operations, IPC SET/RMID, and many others. Removing it before exec eliminates the entry point for the cgroup release_agent escape, most namespace escapes, and many other attacks.

#### A.2.3 core_pattern and sysrq

`/proc/sys/kernel/core_pattern` is writable by root and allows a pipe-based coredump handler (`|/path/to/handler`). If a container process running as UID 0 can write to the host's `/proc/sys/kernel/core_pattern`, it can cause arbitrary code execution on the next crash. Similarly, `/proc/sysrq-trigger` allows triggering kernel debug features. Both require either host procfs being writable inside the container (a misconfiguration) or `CAP_SYS_ADMIN`. The LSM hook `security_file_open` on procfs inodes and seccomp blocking `syslog(2)` / `prctl(2)` with privileged options provide defense.

#### A.2.4 Shocker — CAP_DAC_READ_SEARCH + `open_by_handle_at(2)`

**Mechanism.** `CAP_DAC_READ_SEARCH` allows calling `open_by_handle_at(2)`, which takes a raw `struct file_handle` (containing a raw inode number and filesystem UUID) rather than a path. By iterating over inode numbers from 1, an attacker inside a container can open arbitrary files on the *host* filesystem even through a bind mount or chroot boundary, because the kernel resolves the handle against the underlying filesystem, not the container's namespace view. First demonstrated by Sebastian Krahmer (SuSE) in 2014 as "Shocker."

`capabilities(7)` explicitly lists `open_by_handle_at(2)` as one of the operations guarded by `CAP_DAC_READ_SEARCH`. [man7.org/linux/man-pages/man7/capabilities.7.html]

**Continuous enforcement stops it.** Remove `CAP_DAC_READ_SEARCH` from the container's capability bounding set. seccomp blocking `open_by_handle_at(2)` provides defense-in-depth. The kernel now also checks mount namespace context in `do_handle_open()` for additional protection.

#### A.2.5 CAP_SYS_PTRACE Cross-Process

With `CAP_SYS_PTRACE`, a process can attach to any process visible in its PID namespace, reading and writing its memory. If PID namespace isolation is incomplete (e.g., some host processes are visible), this becomes cross-container or host escape. LSM hook `security_ptrace_access_check` is invoked before each ptrace attachment. The Yama LSM provides a ptrace scope restriction (`/proc/sys/kernel/yama/ptrace_scope`). seccomp can block `ptrace(2)` entirely for production containers.

---

### A.3 Namespace/Mount Runtime Escapes

#### A.3.1 `setns()` into Host Namespace via Leaked FD

If a file descriptor pointing to a host namespace inode (`/proc/1/ns/mnt`, etc.) is leaked into the container (via inherited fds, shared storage, etc.), the container can call `setns(fd, CLONE_NEWNS)` to re-enter the host's mount namespace, bypassing all mount isolation. 

**Continuous enforcement.** seccomp blocking `setns(2)` prevents this entirely. The LSM hook `security_capable` is invoked before `setns()` grants namespace-switching capabilities. krunc's `DESIGN.md` already creates containers with `CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET` — the key is that no fd to host namespaces must be passed to the container.

#### A.3.2 /proc/<hostpid>/root Traversal

Without PID namespace isolation, a container can `chdir("/proc/1/root/")` and then `chroot(".")` to effectively escape the container's chroot into the host filesystem. With PID namespaces (as krunc uses: `CLONE_NEWPID`), `/proc` only shows container-local PIDs. The `/proc/<pid>/root` path also requires `CAP_SYS_CHROOT` or `CAP_SYS_ADMIN` to be useful for escape.

#### A.3.3 Unbounded User Namespaces

Linux has allowed unprivileged user namespace creation (`CLONE_NEWUSER`) by default on many distributions since kernel 3.8. This gives a user "fake" root within the user namespace with capabilities, which has been repeatedly combined with kernel bugs to achieve real-root (CVE-2021-3493 is one example). 

**Continuous enforcement.** `sysctl kernel.unprivileged_userns_clone=0` (distro-specific, e.g., Debian/Ubuntu) or seccomp blocking `clone(CLONE_NEWUSER)` and `unshare(CLONE_NEWUSER)`. Additionally, the LSM hook `security_capable` with capability `CAP_SYS_ADMIN` checked for user namespace creation can be intercepted by a BPF-LSM program.

---

### A.4 Cross-Container Attacks

**IPC namespace sharing.** If two containers share an IPC namespace (not using `CLONE_NEWIPC`), they can communicate via SysV message queues (`msgget`, `msgsnd`, `msgrcv`), shared memory (`shmget`, `shmat`), and semaphores. krunc uses `CLONE_NEWIPC`.

**Shared kernel objects via mmap.** Memory-mapped files (`MAP_SHARED`) from host-mounted paths can be shared between containers that can access the same underlying file. One container writing to the shared mapping affects the other's view.

**/proc cross-visibility.** Without PID namespace isolation, `/proc/[pid]` entries for other containers' processes are visible, allowing cross-container ptrace, `/proc/[pid]/mem` reads, and coredump manipulation.

**Network namespace.** Without `CLONE_NEWNET`, containers share the host's network stack and can sniff traffic, manipulate routing tables (with `CAP_NET_ADMIN`), or attack other containers via loopback.

---

## Part B — In-Kernel Continuous Enforcement Mechanisms

### B.1 seccomp Filters — Continuous, Tamper-Proof Syscall Filtering

**How it works.** A seccomp BPF filter is installed with `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)` or `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, prog)`. The filter runs at kernel entry on *every* syscall, operating on `struct seccomp_data` containing `{nr, arch, instruction_pointer, args[6]}`. The BPF program cannot dereference pointers — it only sees register values — which eliminates TOCTOU races. [kernel.org/doc/html/latest/userspace-api/seccomp_filter.html]

**Persistence and inheritance.** *"If fork/clone and execve are allowed by the filter, any child processes will be constrained to the same filters and system call ABI as the parent."* The filter persists across `execve(2)`. Filters stack monotonically — each additional `prctl(PR_SET_SECCOMP, ...)` adds a filter; they cannot be removed.

**Tamper-proof with `no_new_privs`.** The critical guarantee: *"Prior to use, the task must call `prctl(PR_SET_NO_NEW_PRIVS, 1)`... This requirement ensures that filter programs cannot be applied to child processes with greater privileges."* With `no_new_privs=1` set, SUID/SGID binaries cannot raise privileges, making the seccomp policy impossible to escape via privilege escalation tricks. [man7.org/linux/man-pages/man2/seccomp.2.html]

**Kill on violation.** `SECCOMP_RET_KILL_PROCESS` terminates the *entire process* (not just the thread) immediately, without executing the syscall. The exit status reports `SIGSYS`. `SECCOMP_RET_KILL_THREAD` kills only the triggering thread.

**Usable from a kernel module.** krunc's `container_entry()` function runs in kernel context before `kernel_execve()`. The module can manipulate `current->seccomp` directly by calling `do_set_seccomp_filter()` (an in-kernel helper, exported or wrapped by the shim) before exec. Concretely: the shim can export a `krunc_install_seccomp(struct sock_fprog *)` wrapper.

**Important pitfall.** The seccomp kernel doc notes: *"Always check the arch value!"* when filtering syscall numbers — x86-64 allows x32 and i386 system call conventions with different numbers. A correct filter includes `if (arch != AUDIT_ARCH_X86_64) KILL`.

**Recommended denies for container runtime:**
```
io_uring_setup, bpf, ptrace, open_by_handle_at, setns,
clone(CLONE_NEWUSER|CLONE_NEWNS), unshare(any), mount, umount2,
socket(AF_NETLINK), socket(AF_PACKET), syslog, kexec_load,
perf_event_open, process_vm_readv, process_vm_writev, splice, tee,
nfsservctl, pivot_root, add_key, keyctl, request_key, quotactl
```

---

### B.2 Capability Bounding Set — Irreversible Privilege Reduction

**How it works.** Each process has four capability sets: *effective*, *permitted*, *inheritable*, and *bounding*. The bounding set acts as a ceiling: it is AND'd with the file's permitted capability set at `execve()`. Capabilities dropped from the bounding set via `prctl(PR_CAPBSET_DROP, cap)` can *never be re-acquired* by the process or any descendant, regardless of SUID files or file capabilities. [man7.org/linux/man-pages/man7/capabilities.7.html]

**Tamper-proof.** `PR_CAPBSET_DROP` is monotonically decreasing — it can only remove capabilities, never add. A container cannot re-grant itself a dropped capability.

**Persistence.** The bounding set is inherited across `fork()`/`clone()`. It is NOT inherited across `execve()` in the sense that the new program's permitted set = (file permitted ∩ bounding set), so the bounding set constrains all future capability acquisition.

**From a kernel module.** Before `kernel_execve()`, `container_entry()` has direct kernel access to `current->cred`. The module (via the C shim) can call `cap_lower(cred->cap_bset, cap)` to strip capabilities. This is exactly what `runc` does in userspace via `capset(2)`.

**Critical drops for containers:**
```
CAP_SYS_ADMIN       # ALL namespace/mount/IPC operations, eBPF privileged
CAP_SYS_MODULE      # Loading kernel modules
CAP_SYS_RAWIO       # Raw device I/O
CAP_SYS_PTRACE      # ptrace of any process
CAP_DAC_READ_SEARCH # open_by_handle_at (Shocker)
CAP_NET_ADMIN       # Routing table manipulation, raw socket control
CAP_NET_RAW         # Raw/packet sockets
CAP_MKNOD           # Device node creation
CAP_SYS_BOOT        # Reboot/kexec
CAP_SETFCAP         # Set file capabilities
CAP_MAC_ADMIN       # LSM MAC override
CAP_SYS_CHROOT      # chroot(2) (already isolated, but defense-in-depth)
CAP_SYS_TIME        # System time changes
```

`capabilities(7)` notes that `CAP_BPF` (since Linux 5.8) was specifically split from `CAP_SYS_ADMIN` to provide more granular control over BPF operations.

---

### B.3 LSM Hooks — The Traditional Architecture and the Loadable-Module Wall

**How LSMs work.** The Linux Security Module framework adds `security_*()` wrapper functions throughout the kernel at *access control decision points* — before operations like file open, inode create, mount, signal send, ptrace. Each wrapper calls all registered LSM hooks in order; if any returns non-zero, the operation is denied. The framework is documented in `security/security.c` and `include/linux/lsm_hooks.h`. [kernel.org/doc/html/latest/security/lsm.html]

**Critical architectural constraint for kernel modules.** `DEFINE_LSM(lsm)` places an `lsm_info` struct in the **`.lsm_info.init`** ELF section, which is processed only during `security_init()` at boot. After that:

- `static_calls_table` (the dispatch table for all LSM hooks) is marked **`__ro_after_init`** — it is literally made read-only after kernel initialization completes. [include/linux/lsm_hooks.h: `extern struct lsm_static_calls_table static_calls_table __ro_after_init;`]
- `security_add_hooks()` is declared as `extern void security_add_hooks(...)` in `lsm_hooks.h` but **is NOT `EXPORT_SYMBOL`'d** — confirmed by searching `security/security.c`. A loadable module cannot call it.
- Even if it were exported, the `static_calls_table` being `__ro_after_init` means a post-boot call would write to read-only memory, causing a kernel BUG/oops.

**Verdict: A loadable kernel module CANNOT register traditional LSM hooks post-boot.** This is intentional — it prevents a rogue module from hijacking security decisions after the system is initialized.

**LSM Stacking.** The kernel supports multiple LSMs simultaneously (enabled via `CONFIG_LSM` kernel parameter or `security=` boot arg). Active LSMs are listed in `/sys/kernel/security/lsm`. Hooks are called in order: capabilities first, then "minor" LSMs (Yama, Landlock), then one "major" LSM (SELinux or AppArmor). BPF-LSM is a special stackable LSM that can coexist with all others. [kernel.org/doc/html/latest/admin-guide/LSM/index.html: *"The capability module will always be first, followed by any 'minor' modules and then the one 'major' module"*]

**The approved runtime hook mechanism: BPF-LSM** (see B.5 below).

**The full LSM hook catalogue relevant to containers** (from `security/security.c`, `include/linux/lsm_hook_defs.h`):

| Hook | Trigger | Container-relevant policy |
|------|---------|--------------------------|
| `security_bprm_check_security` | Before exec | Validate binary; block privileged execs |
| `security_file_open` | Before file open | Block writes to `/proc/sys/kernel/*` |
| `security_inode_permission` | Inode access check | Enforce read-only on sensitive paths |
| `security_sb_mount` | Before mount(2) | Block cgroupfs, procfs, devtmpfs mounts |
| `security_move_mount` | Before move_mount(5) | Block bind mount manipulation |
| `security_task_kill` | Before signal send | Restrict cross-container signals |
| `security_ptrace_access_check` | Before ptrace | Deny cross-PID-namespace ptrace |
| `security_capable` | Capability check | Per-container capability policy |
| `security_socket_create` | Before socket create | Block AF_NETLINK, AF_PACKET |
| `security_unix_stream_connect` | Before Unix socket connect | Restrict abstract socket namespace |
| `security_path_mknod` | Before mknod | Block device creation |

---

### B.4 Landlock — Unprivileged, Inheritable, Tamper-Proof Filesystem Confinement

**What Landlock is.** Landlock (introduced Linux 5.13, ABI v1) is a stackable LSM that allows *any process* to sandbox itself and its descendants without requiring root privileges. It is explicitly designed for defense-in-depth sandboxing. From `landlock(7)`: *"Landlock is an access-control system that enables any processes to securely restrict themselves and their future children. Because Landlock is a stackable Linux Security Module (LSM), it makes it possible to create safe security sandboxes as new security layers in addition to the existing system-wide access-controls."* [man7.org/linux/man-pages/man7/landlock.7.html]

**Three-syscall API.** [man7.org/linux/man-pages/man2/landlock_create_ruleset.2.html] [man7.org/linux/man-pages/man2/landlock_restrict_self.2.html]

```c
// 1. Create a ruleset declaring all access rights this domain handles
int ruleset_fd = landlock_create_ruleset(&ruleset_attr,
    sizeof(ruleset_attr), 0);    // Linux 5.13

// 2. Add specific allow-rules for paths/ports
struct landlock_path_beneath_attr beneath = {
    .allowed_access = LANDLOCK_ACCESS_FS_READ_FILE |
                      LANDLOCK_ACCESS_FS_READ_DIR  |
                      LANDLOCK_ACCESS_FS_EXECUTE,
    .parent_fd = open("/usr", O_PATH | O_CLOEXEC),
};
landlock_add_rule(ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &beneath, 0);

// 3. Apply: enforce on self and all future children
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // Required unless CAP_SYS_ADMIN
landlock_restrict_self(ruleset_fd, 0);
```

**ABI version history:**
- ABI v1 (Linux 5.13): Filesystem rules
- ABI v2 (Linux 5.19): `LANDLOCK_ACCESS_FS_REFER` (cross-directory links)
- ABI v3 (Linux 6.2): `LANDLOCK_ACCESS_FS_TRUNCATE`
- ABI v4 (Linux 6.3): Network rules — TCP bind/connect port restrictions
- ABI v5 (Linux 6.4): `LANDLOCK_ACCESS_FS_IOCTL_DEV`
- ABI v6 (Linux 6.8): IPC scoping — `LANDLOCK_SCOPE_SIGNAL`, `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`
- ABI v8 (Linux 6.12): `LANDLOCK_RESTRICT_SELF_TSYNC` — applies policy to ALL threads atomically

**Tamper-proof from inside the container.** Once `landlock_restrict_self()` is called, the process's Landlock domain is a read-only ruleset that can only be *further restricted* — never loosened. `landlock_restrict_self(2)` documentation: *"A domain can only be updated in such a way that the constraints of each past and future composed rulesets will restrict the thread and its future children for their entire life."* There is no `landlock_unrestrict_self()`.

**Inheritance.** *"Every new thread resulting from a clone(2) inherits Landlock domain restrictions from its parent."* This means a Landlock policy applied before `kernel_execve()` is automatically enforced on the container's PID 1 and every process it spawns.

**Can krunc apply Landlock before exec?** Yes, with a caveat. The `landlock_restrict_self(2)` man page states: *"either the caller must have the CAP_SYS_ADMIN capability in its user namespace, or the thread must already have the no_new_privs bit set."* Since `container_entry()` runs in kernel context with all capabilities, `CAP_SYS_ADMIN` is satisfied. The shim can export a wrapper around `sys_landlock_restrict_self()` or its internal implementation in `security/landlock/syscalls.c`.

**Network confinement (ABI v4+, Linux 6.3):**
```c
struct landlock_net_port_attr net = {
    .allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
    .port = 443,   // Allow only HTTPS outbound
};
landlock_add_rule(ruleset_fd, LANDLOCK_RULE_NET_PORT, &net, 0);
// All other TCP connect/bind denied
```

**IPC scoping (ABI v6+, Linux 6.8).** `LANDLOCK_SCOPE_SIGNAL` restricts the container from sending signals to processes outside its Landlock domain (including the host). `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` prevents connection to abstract Unix sockets created outside the domain — blocking many container-to-host IPC channels.

**The OverlayFS caveat.** Landlock is inode-based, not path-based. An OverlayFS mount point has different inodes from its lower/upper layers, so a rule on the lower layer does not automatically apply to the merged hierarchy. `landlock(7)`: *"A policy restricting an OverlayFS layer will not restrict the resulted merged hierarchy, and vice versa."* For containers using overlay rootfs, Landlock rules must be applied to the *merged* path.

---

### B.5 BPF-LSM — Runtime Per-Container Policy via BPF Hook Attachment

**What BPF-LSM is.** With `CONFIG_BPF_LSM=y` and `security=...,bpf` in the boot args, the BPF-LSM is registered as a stackable LSM. It allows privileged users to attach BPF programs of type `BPF_PROG_TYPE_LSM` to any LSM hook *at runtime*. From `bpf/prog_lsm.rst`: *"These BPF programs allow runtime instrumentation of the LSM hooks by privileged users to implement system-wide MAC and Audit policies using eBPF."* [kernel.org/doc/html/latest/bpf/prog_lsm.html]

**Attachment mechanism:**
```c
// Load a BPF-LSM program attached to, e.g., security_socket_create
SEC("lsm/socket_create")
int BPF_PROG(deny_netlink, int family, int type, int protocol, int kern) {
    if (bpf_get_current_cgroup_id() == CONTAINER_CGROUP_ID &&
        family == AF_NETLINK)
        return -EPERM;
    return 0;
}
```
A BPF-LSM program can:
- Return `-EPERM` to deny the operation
- Call `bpf_send_signal(SIGKILL)` to kill the triggering task (actively kill the container)
- Access `bpf_get_current_task()` → `task_struct` for deep inspection
- Use `bpf_current_task_under_cgroup()` for per-container policy dispatch

**Per-container policy via cgroup.** krunc places each container in its own cgroup (planned, per `DESIGN.md` §9 step 1). A BPF-LSM program checks `bpf_get_current_cgroup_id()` and applies container-specific allow-lists. This enables precise, per-container policies enforced continuously at every LSM hook invocation.

**From a Rust kernel module.** A kernel module (running with full capabilities) can use the kernel's internal BPF loading infrastructure (`bpf_prog_load_check_attr()`, `bpf_prog_alloc()`, BPF verifier, `bpf_trampoline_link_prog()`) to load and attach BPF-LSM programs without going through the `bpf(2)` syscall. This gives krunc the ability to atomically install per-container BPF-LSM policy as part of container creation. Alternatively — and more maintainably — a privileged userspace daemon loaded by the module can manage BPF program lifecycle.

**Kill-on-violation via `bpf_send_signal`.** The BPF helper `bpf_send_signal(sig)` allows a BPF-LSM program to send an arbitrary signal to the current task. Calling `bpf_send_signal(SIGKILL)` from a `lsm/socket_create` hook that detects a policy violation immediately kills the container process — *while still returning -EPERM* to deny the operation. This is the preferred active-response mechanism.

**Detachment/persistence.** BPF-LSM programs are attached via a `bpf_link`; the link persists until explicitly destroyed (`bpf_link__destroy()`) or the loading process exits. For production use, links can be pinned to a BPF filesystem (`/sys/fs/bpf/`) to persist across the loading process's lifetime.

**Limitation.** BPF-LSM programs are globally applied (though can be cgroup-scoped). Multiple containers with different policies require multiple BPF programs or one BPF program with a per-cgroup policy table (BPF maps keyed by cgroup ID). This is how Cilium and Falco operate.

---

### B.6 Per-Container "Kill on Policy Violation"

The three complementary mechanisms for active termination:

**1. seccomp `SECCOMP_RET_KILL_PROCESS`.** The most reliable: fires atomically at the syscall entry point before the syscall executes. The container process dies with `SIGSYS` status. Cannot be intercepted by the container (unlike `SIGKILL` which can be temporarily masked, the kill here happens before userspace signal handling). Appropriate for syscalls that should *never* be called: `io_uring_setup`, `bpf`, `open_by_handle_at`, etc.

**2. BPF-LSM `bpf_send_signal(SIGKILL)`.** Applied at semantic decision points *within* permitted syscalls. For example, `socket(AF_INET, ...)` is permitted but `socket(AF_NETLINK, ...)` is not — a seccomp filter cannot distinguish without socket-type filtering (it can, but the BPF-LSM approach is cleaner for semantic policies). The `bpf_send_signal` helper sends the signal to the current task and is processed on the return to userspace.

**3. krunc kernel module `krunc_kill(pid, SIGKILL)`.** Already implemented in the shim (`krunc_kill` wraps `kill_pid()` with error handling). The module can kill any container by host PID from any context. This is the fallback for escape attempts detected via monitoring (audit logs, seccomp unotify notifications, etc.).

**Seccomp user notification (`SECCOMP_RET_USER_NOTIF`).** For policy decisions that require more context than pure syscall number/arg filtering, `SECCOMP_FILTER_FLAG_NEW_LISTENER` returns a notification file descriptor. krunc's parent process can `poll()` on this fd to receive notifications about blocked syscalls and make dynamic policy decisions. This enables a "detect-and-kill" workflow: block a suspicious syscall, inspect it in user context, kill the container if malicious.

---

## Part C — The Honest Limit: One Kernel, Shared Attack Surface

### C.1 The Fundamental Constraint

Containers share one kernel. Every Linux kernel CVE described in Part A affects containers running on that kernel version *regardless of all user-namespace, capability, or seccomp defenses* — as long as the exploit's entry-point syscall is allowed. There is no namespace that protects the kernel from itself.

gVisor's security documentation states this precisely: *"Although the System API is exposed to applications by design, bugs and race conditions within the kernel or hypervisor may occasionally be exploitable via the API. This is common in part due to the fact that most kernels and hypervisors are written in C, which is well-suited to interfacing with hardware but often prone to security issues."* [gvisor.dev/docs/architecture_guide/security/]

### C.2 gVisor's Threat Model

gVisor's **Sentry** is a complete reimplementation of the Linux kernel ABI in Go, running in userspace. Container processes' syscalls are intercepted by the Sentry (never reaching the host kernel directly). The Sentry then translates them into a minimal set of host syscalls — roughly 50, vs the ~350+ in the full Linux ABI.

**First principle**: *"No system call is passed through directly to the host. Every supported call has an independent implementation in the Sentry, that is unlikely to suffer from identical vulnerabilities."* [gvisor.dev/docs/architecture_guide/security/]

**Second principle**: *"The host surface exposed to the Sentry is minimized... The Sentry is not permitted to open new files, create new sockets or do many other interesting things on the host."* The Sentry itself runs under a seccomp filter — so even if the Sentry is exploited, the attacker only has the ~50 host syscalls the Sentry uses.

**What gVisor protects against**: arbitrary kernel 0-days exploitable through the full syscall surface. A Dirty Pipe exploit attempted inside gVisor would invoke the Sentry's Go implementation of `splice()`/pipe operations, which has entirely different (and memory-safe) code — the host kernel's vulnerable C path is never reached.

**What gVisor does NOT protect against**: hardware side channels (Spectre, L1TF — the same mitigations apply), hypervisor-level bugs (when using KVM-based platform), bugs in the Sentry itself, and non-syscall attack vectors.

### C.3 Kata Containers' Threat Model

Kata Containers runs each container workload inside a lightweight VM (QEMU/Cloud Hypervisor + bare-metal kernel). The container sees its own dedicated kernel. An exploit that escapes the container into "the kernel" only reaches the *VM's kernel*, not the host. The host kernel's attack surface is reduced to the KVM interface and virtio device emulation.

**Defense boundary**: The hypervisor (KVM + host kernel) is significantly smaller and harder to exploit than a full user-facing Linux kernel ABI. Hardware virtualization (VT-x/AMD-V) provides a hardware-enforced boundary between guest and host.

**Trade-off**: Performance overhead (VM startup time, memory overhead for multiple kernels), and hypervisor bugs are still possible (Cloudburst, VENOM, etc.).

### C.4 Where krunc Sits

```
                    Attack surface (smaller = better)
    ┌────────────────────────────────────────────────────────────────────┐
    │ bare container (no hardening) — ~350 syscalls, all capabilities   │
    ├────────────────────────────────────────────────────────────────────┤
    │ + seccomp + cap-drop + Landlock + BPF-LSM (krunc-hardened)        │
    │   ~50-100 syscalls, no CAP_SYS_ADMIN, filesystem-confined         │
    │   → still shares host kernel; patched 0-days in allowed syscalls  │
    │     still land on host kernel code                                │
    ├────────────────────────────────────────────────────────────────────┤
    │ gVisor — ~50 host syscalls, Sentry implements the ABI in Go        │
    │   → most kernel C bugs unreachable; Sentry itself can have bugs   │
    ├────────────────────────────────────────────────────────────────────┤
    │ Kata Containers — VM boundary, dedicated kernel per container      │
    │   → kernel bugs only affect VM kernel; host protected by KVM      │
    └────────────────────────────────────────────────────────────────────┘
```

**krunc's value proposition** in this stack is *defense-in-depth with active detection and response*:
- **Minimized kernel attack surface**: seccomp reduces the set of syscalls that can trigger kernel bugs
- **Removed capabilities**: prevents entire exploit classes (cgroup escape, Shocker, raw socket manipulation) even on patched kernels
- **Continuous confinement**: Landlock and BPF-LSM enforce policy for the container's entire lifetime, not just at startup
- **Active termination**: escape attempts are detected and the container is killed, not just denied
- **Tamper-proof**: with `no_new_privs=1` + cap bounding set, the container cannot relax any policy

**But krunc is explicitly NOT VM-grade isolation.** This must be stated in its documentation. For sensitive workloads or when running truly untrusted code, gVisor or Kata Containers should be used. krunc's hardened mode reduces the *probability* of kernel exploitation through defense-in-depth; it does not eliminate the possibility.

---

## Concrete Recommendation: How krunc Should Layer These Mechanisms

This is the implementation roadmap for `DESIGN.md` §9 "Privilege reduction" and beyond.

### Layer 1: Capability Bounding Set (Drop Before Exec) — **Immediate**

In `container_entry()`, before `kernel_execve()`, drop all non-essential capabilities. The shim already has kernel access to `current->cred`. A new `krunc_drop_capabilities(cap_mask)` shim function can call `cap_lower()` on `cred->cap_bset` and clear the effective/permitted sets.

**Minimal viable cap set for a generic server container**: `{ CAP_NET_BIND_SERVICE, CAP_SETUID, CAP_SETGID, CAP_DAC_OVERRIDE }`. Drop everything else.

### Layer 2: `no_new_privs` — **Immediate**

Set `current->no_new_privs = 1` before exec. This makes seccomp + Landlock tamper-proof: no SUID binary can restore dropped capabilities.

### Layer 3: seccomp Filter (Syscall Allow-list) — **High Priority**

Install a seccomp BPF filter via a new `krunc_install_seccomp(prog)` shim function before `kernel_execve()`. The OCI spec's `config.json` `linux.seccomp` field maps directly to this. For the initial implementation, use Docker's default seccomp profile (300+ lines of BPF) as a starting point, compiled into the module.

**Minimum additional denies beyond Docker defaults**: `io_uring_setup`, `bpf`, `open_by_handle_at`, `setns`, `splice` (if not needed), `nfsservctl`.

**Return code**: Use `SECCOMP_RET_KILL_PROCESS` for clearly-malicious syscalls, `SECCOMP_RET_ERRNO(EPERM)` for grey-area ones (to avoid crashing well-behaved programs).

### Layer 4: Landlock (Filesystem Confinement) — **Medium Priority**

Before exec, call `sys_landlock_create_ruleset()` + `sys_landlock_add_rule()` + `sys_landlock_restrict_self()` (via shim wrappers). Allow only:
- Container rootfs: `READ_FILE | READ_DIR | EXECUTE | WRITE_FILE | MAKE_REG | ...`
- `/proc` (container-local): `READ_FILE | READ_DIR`
- No `REFER` (prevent cross-directory linking to host paths)

For ABI v4+ kernels, restrict TCP connects to ports declared in the OCI spec.
For ABI v6+ kernels, add `LANDLOCK_SCOPE_SIGNAL` to prevent the container from signaling host processes.

### Layer 5: BPF-LSM Per-Container Policy (Active Detection + Kill) — **Future Work**

Load a BPF-LSM program (compiled into the module as a byte array, or loaded from `/etc/krunc/bpf/policy.o`) that:
1. Identifies container processes by cgroup ID (`bpf_get_current_cgroup_id()`)
2. Enforces semantic policy (e.g., block all `AF_NETLINK` socket creation, block `CAP_SYS_ADMIN` checks, block `/proc/sys/kernel/core_pattern` writes)
3. Calls `bpf_send_signal(SIGKILL)` on detected escape attempts

This layer provides the "continuous" enforcement that survives even if seccomp is bypassed via a kernel bug: the BPF-LSM hook fires at semantic checkpoints deeper in the kernel, at different code paths than the syscall entry.

### Layer 6: Seccomp User-Notify for Audit/Forensics — **Future Work**

Install a seccomp filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER` for a subset of sensitive syscalls. krunc's registry daemon monitors these notifications and logs or kills on policy violations. This gives visibility into escape attempts for forensics.

### Stated Limits (Must Be in Documentation)

1. **Kernel 0-days through allowed syscalls**: Any CVE in a syscall the container is permitted to call (e.g., a future `mmap()` bug) can still be exploited. Mitigated only by kernel patching and syscall surface minimization.
2. **BPF verifier bugs**: If the `bpf` syscall is blocked (it should be), the BPF-LSM programs loaded by krunc itself could theoretically be targeted — but the module loads them from kernel context with the verifier running, and the container cannot affect this.
3. **The module itself**: krunc is a kernel module; a bug in krunc's Rust code could itself be exploited by a container to gain kernel code execution. Rust's memory safety eliminates most classes of bugs but not logic bugs.
4. **Not VM-grade**: For multi-tenant SaaS workloads or truly adversarial code, use gVisor (`runsc`) or Kata Containers instead of or in addition to krunc.

---

## Citation Index

| Source | Used for |
|--------|----------|
| [NVD CVE-2016-5195](https://nvd.nist.gov/vuln/detail/CVE-2016-5195) | Dirty COW details, active exploitation |
| [NVD CVE-2022-0847](https://nvd.nist.gov/vuln/detail/CVE-2022-0847); [dirtypipe.cm4all.com](https://dirtypipe.cm4all.com/) | Dirty Pipe root cause |
| [NVD CVE-2021-3493](https://nvd.nist.gov/vuln/detail/CVE-2021-3493) | OverlayFS + user-namespace escape |
| [NVD CVE-2022-32250](https://nvd.nist.gov/vuln/detail/CVE-2022-32250) | nf_tables UAF |
| [NVD CVE-2023-3269](https://nvd.nist.gov/vuln/detail/CVE-2023-3269) | StackRot VMA UAF |
| [NVD CVE-2024-1086](https://nvd.nist.gov/vuln/detail/CVE-2024-1086); [pwning.tech/nftables](https://pwning.tech/nftables/) | nf_tables double-free |
| [kernel.org seccomp_filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html) | seccomp architecture, BPF TOCTOU safety, inheritance |
| [man2 seccomp](https://www.man7.org/linux/man-pages/man2/seccomp.2.html) | `SECCOMP_SET_MODE_FILTER`, `no_new_privs`, listener fd |
| [man7 landlock](https://www.man7.org/linux/man-pages/man7/landlock.7.html) | Landlock ABI, filesystem actions, inheritance, IPC scoping |
| [man2 landlock_create_ruleset](https://www.man7.org/linux/man-pages/man2/landlock_create_ruleset.2.html) | Ruleset creation API |
| [man2 landlock_restrict_self](https://www.man7.org/linux/man-pages/man2/landlock_restrict_self.2.html) | Restriction API, TSYNC, no_new_privs requirement |
| [kernel.org landlock internal](https://www.kernel.org/doc/html/latest/security/landlock.html) | `landlock_ruleset`, `landlock_layer`, `landlock_hierarchy` structs |
| [kernel.org userspace landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html) | ABI version compat code, network rules, IPC scoping |
| [kernel.org lsm](https://www.kernel.org/doc/html/latest/security/lsm.html) | LSM framework, `security_add_hooks()`, stacking, blob architecture |
| [kernel.org lsm-development](https://www.kernel.org/doc/html/latest/security/lsm-development.html) | Full hook catalogue (`security_sb_mount`, `security_file_ioctl`, etc.) |
| [kernel.org LSM/index](https://www.kernel.org/doc/html/latest/admin-guide/LSM/index.html) | Load order, `CONFIG_DEFAULT_SECURITY`, `/sys/kernel/security/lsm` |
| [kernel.org bpf/prog_lsm](https://www.kernel.org/doc/html/latest/bpf/prog_lsm.html) | BPF-LSM program structure, attachment, `bpf_send_signal` |
| [include/linux/lsm_hooks.h](https://github.com/torvalds/linux/blob/master/include/linux/lsm_hooks.h) | `DEFINE_LSM()` → `.lsm_info.init` section; `static_calls_table __ro_after_init`; `security_add_hooks()` NOT exported |
| [kernel.org cgroup-v1](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v1/cgroups.html) §1.4 | `notify_on_release`, `release_agent` mechanism |
| [kernel.org credentials](https://www.kernel.org/doc/html/latest/security/credentials.html) | `struct cred`, cap sets, `prepare_creds`/`commit_creds` |
| [man7 capabilities](https://www.man7.org/linux/man-pages/man7/capabilities.7.html) | Cap definitions: `CAP_DAC_READ_SEARCH`/`open_by_handle_at`, `CAP_SYS_ADMIN` operations |
| [gVisor security](https://gvisor.dev/docs/architecture_guide/security/) | Sentry threat model, syscall interception, ~50 host syscall surface |
| `docs/DESIGN.md` §9 | Current krunc limitations: no seccomp, no cap drop, chroot not pivot_root |
| `module/krunc.rs:51-70` | FFI bindings: `krunc_spawn`, `kernel_execve`, `krunc_chroot`, `krunc_kill` |
| `module/krunc.rs:42-48` | CLONE_NEW* flags, two-phase create/start gate |

---

## Summary Table: Enforcement Mechanism Properties

| Mechanism | Continuous? | Tamper-proof from inside? | Post-setup? | Loadable module? | Kills on violation? |
|-----------|------------|--------------------------|-------------|-----------------|---------------------|
| **seccomp filter** | ✅ Every syscall | ✅ With `no_new_privs=1` | ✅ Set before exec, lasts lifetime | ✅ Via shim before exec | ✅ `SECCOMP_RET_KILL_PROCESS` |
| **Cap bounding set** | ✅ Every `execve` + capable() | ✅ Drop-only, irreversible | ✅ Set before exec, inherited | ✅ Direct `cred` manipulation | ❌ (prevents capabilities, doesn't kill) |
| **Landlock** | ✅ Every file/net op | ✅ Can only tighten | ✅ Set before exec, inherited across all descendants | ✅ Via shim (kernel context has `CAP_SYS_ADMIN`) | ❌ Returns `-EACCES`/`-EPERM` |
| **Traditional LSM hooks** | ✅ Every hook call | ✅ `__ro_after_init` | ✅ Boot-time registered | ❌ **NOT from loadable module** | ❌ Direct only via additional mechanism |
| **BPF-LSM** | ✅ Every hook call | ✅ Container can't remove (can't use `bpf()` if seccomp blocks it) | ✅ Load any time with `CAP_BPF`+`CAP_MAC_ADMIN` | ✅ Module loads BPF prog internally | ✅ `bpf_send_signal(SIGKILL)` |
| **cgroup + PID ns** | ✅ Lifetime | ✅ Needs `CAP_SYS_ADMIN` to escape | ✅ Namespace persists | ✅ Already done in krunc | ❌ (isolation, not detection) |