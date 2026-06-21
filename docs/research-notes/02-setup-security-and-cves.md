Agent completed. agent_id: security-research, agent_type: research, status: completed, description: Research container security boundary + CVEs, elapsed: 697s, total_turns: 0, duration: 576s

I now have all the data needed for a comprehensive, deeply-cited report. Let me compile it.

---

# Security-Critical Analysis of Linux Container Setup: Kernel vs. Userspace Split

## 1. Summary

runc, youki, and crun all share a fundamental architectural vulnerability: they interpose an intermediate privileged process ("runc init") that lives in a hybrid state—partially inside the container's namespaces but still holding host-level resources—before executing the actual container payload. Every critical container CVE from 2016–2024 exploits this transition window in some form: leaked file descriptors, procfs magic links, ptrace races, or capability inheritance bugs. A Rust kernel module that performs namespace creation, mount setup, capability/seccomp application, and execve atomically eliminates the init process entirely, collapsing the multi-syscall window to a single kernel-context operation. This report documents the exact attack surface, the security-critical ordering of every confinement step, what belongs in the kernel vs. userspace, and the kernel primitives that already exist to support this design.

---

## 2. The Historical Attack Surface: CVE Analysis

### 2.1 CVE-2019-5736 — runc `/proc/self/exe` Overwrite

**NVD**: "runc through 1.0-rc6 allows attackers to overwrite the host runc binary and thus gain root-level code execution on the host."  
**Disclosure**: Aleksa Sarai, oss-security@openwall.com, 2019-02-11: https://www.openwall.com/lists/oss-security/2019/02/11/2  
**CVSS**: 7.2 (AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:H)

#### Root Cause

The "runc init" process—the privileged intermediate process that sets up the container—runs its binary from `/proc/self/exe`, which is a **procfs magic link** pointing to the actual on-disk runc binary on the **host filesystem**. A container process running as root can:

1. Open `/proc/self/fd/<N>` where `<N>` is a file descriptor that resolves through the host's procfs to the runc binary (reachable because the init process's `/proc/self/exe` is visible in `/proc/<container-pid>/exe` from inside the container, or via the `#!` shebang trick to keep an open write fd).
2. Open that fd for writing (exploiting the fact that the kernel allows re-opening a magic link as long as the original binary is still "running").
3. Overwrite the binary in-place, since the running "runc init" process has that binary open as its executable.

The critical insight: **`/proc/self/exe` is a procfs magic link that resolves to the *host* filesystem path of the running binary.** Any process inside the container that could access this link—whether directly or through the init process's `/proc/<pid>/exe`—could get a writable handle to the host runc binary.

#### runc's Fix

`libcontainer/exeseal/cloned_binary_linux.go` — runc now clones itself into a sealed `memfd` before executing "runc init":

```go
// CloneSelfExe makes a clone of the current process's binary (through
// /proc/self/exe). This binary can then be used for "runc init" in order to
// make sure the container process can never resolve the original runc binary.
// For more details on why this is necessary, see CVE-2019-5736.
func CloneSelfExe(tmpDir string) (*os.File, error) { ... }
```
`opencontainers/runc:libcontainer/exeseal/cloned_binary_linux.go` (SHA a3c6e59)

The memfd is sealed with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE` and optionally `F_SEAL_EXEC` (Linux 6.3), making it immutable. The init process's `/proc/self/exe` then points to an anonymous memfd with no on-disk counterpart, not the host binary.

```go
const baseMemfdSeals = unix.F_SEAL_SEAL | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_WRITE
```
`opencontainers/runc:libcontainer/exeseal/cloned_binary_linux.go:45`

#### Would Kernel-Side Atomic Setup Prevent This?

**Yes, completely.** If the kernel module performs all setup and directly execve()s the container payload with no intermediate "runc init" process, there is no runtime binary accessible via procfs magic links. The kernel module itself is not a userspace binary with a `/proc/self/exe` link—kernel code has no userspace ELF to overwrite. The entire attack class dissolves: no magic link, no overwrite target, no exploit.

---

### 2.2 CVE-2024-21626 — runc Leaked FD / WORKDIR Container Escape

**Advisory**: https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv  
**Affected**: runc ≤ 1.1.11  
**CVSS**: Up to 8.6 (Attack 3a)

#### Root Cause

runc's multi-process init architecture (runc parent → runc init → container process) requires passing configuration and synchronization via internal file descriptors. The vulnerability has two components:

1. **FD leak**: An internal fd to `/sys/fs/cgroup` on the **host** filesystem (opened with `O_RDONLY` but without `O_CLOEXEC`) leaked through exec into the "runc init" process. This was introduced in v1.0.0-rc93. The leaked fd number was predictable (typically fd 7, based on Go runtime file opening order).

2. **Missing CWD verification**: runc did not verify that the final working directory was inside the container's mount namespace root after `chdir(2)`. Linux marks a CWD that is outside the namespace root with `(unreachable)` prefix on `/proc/self/cwd`, and `getcwd()` returns `ENOENT`—but runc never checked this.

**Attack 1** (malicious image): Set `process.cwd` to `/proc/self/fd/7/` in the OCI spec. When runc init executes the container process, its working directory is on the **host filesystem**, allowing full read/write access.

**Attack 2** (from inside container): A process inside the container replaces its expected cwd path with a symlink to `/proc/self/fd/7/` before `runc exec --cwd` resolves it. After exec, the new process has its CWD in the host namespace and `PR_SET_DUMPABLE` is reset, making `/proc/<pid>/cwd` accessible.

**Attacks 3a/3b**: Use `/proc/self/fd/7/../../../bin/bash` as the `process.args` binary path to execve a host binary, then use the running process's `/proc/self/exe` handle to overwrite the host binary.

The advisory notes CWD escape: `"runc also did not verify that the final working directory was inside the container's mount namespace root after calling chdir(2) (as we have already joined the container namespace, it was incorrectly assumed there would be no way to chdir outside the container after pivot_root(2))"`

#### runc's Four Fixes

From `standard_init_linux.go` (commit after 1.1.12):

```go
// verifyCwd ensures that the current directory is actually inside the mount
// namespace root of the current process.
func verifyCwd() error {
    if wd, err := linux.Getwd(); errors.Is(err, unix.ENOENT) {
        return errors.New("current working directory is outside of container mount namespace root -- possible container breakout detected")
    }
    ...
}
```
`opencontainers/runc:libcontainer/init_linux.go` (SHA 6dad31)

```go
// Close all file descriptors we are not passing to the container. This is
// necessary because the execve target could use internal runc fds as the
// execve path, potentially giving access to binary files from the host
// (which can then be opened by container processes, leading to container
// escapes). Note that because this operation will close any open file
// descriptors...
// See CVE-2024-21626 for more information as to why this protection is necessary.
if err := utils.UnsafeCloseFrom(l.config.PassedFilesCount + 3); err != nil {
    return err
}
```
`opencontainers/runc:libcontainer/standard_init_linux.go` (SHA 933c1d)

#### Would Kernel-Side Atomic Setup Prevent This?

**Yes, entirely.** The kernel module holds all file descriptors in kernel space; there is no "runc init" userspace process that inherits leaked fds. The container process is exec'd from kernel context—fd table cleanup is done atomically before the first userspace instruction of the container payload runs. There is no intermediate CWD to manipulate, no `/proc/self/fd/7` to exploit, because there is no intermediate process.

---

### 2.3 CVE-2022-29162 — runc `exec --cap` Inheritable Capabilities

**Advisory**: https://github.com/opencontainers/runc/security/advisories/GHSA-f3fp-gc8g-vw66  
**Affected**: runc < 1.1.2  
**Reporter**: Andrew G. Morgan (libcap maintainer)

#### Root Cause

When `runc exec --cap CAP_NET_BIND_SERVICE` (for example) was used to grant additional capabilities to a process, runc incorrectly placed the extra capabilities in the **inheritable** set, not just the effective/permitted sets.

The Linux capability model defines five sets: **effective**, **permitted**, **inheritable**, **bounding**, and **ambient**. The inheritable set has a specific meaning: for file capabilities (set via `setcap`), the file's inheritable capability mask is AND-ed with the process's inheritable set to determine what gets added to the permitted set during execve. This means: if a binary has `cap_net_bind_service+ei` set in its file capabilities, and the process runs with `cap_net_bind_service` in its inheritable set, the binary can elevate that capability to permitted during exec—*even if the process wasn't explicitly granted it as permitted*.

This creates an atypical Linux environment: programs installed inside the container with inheritable file capabilities (common in distributions) could silently gain elevated permissions without being explicitly configured to do so.

The advisory specifies: "This bug did not affect the container security sandbox as the inheritable set never contained more capabilities than were included in the container's bounding set." However, it violated the principle of least privilege and could silently enable file-capability escalation within the container.

#### runc's Fix

`libcontainer/capabilities/capabilities.go` explicitly manages all five sets:

```go
// ApplyCaps sets all the capabilities for the current process in the config.
func (c *Caps) ApplyCaps() error {
    c.pid.Clear(capability.CAPS | capability.BOUNDS)
    for _, g := range []capability.CapType{
        capability.EFFECTIVE,
        capability.PERMITTED,
        capability.INHERITABLE,
        capability.BOUNDING,
    } {
        c.pid.Set(g, c.caps[g]...)
    }
    ...
}
```
`opencontainers/runc:libcontainer/capabilities/capabilities.go:88-100` (SHA 6ac6dc)

The inheritable set is now explicitly cleared and set from the OCI spec, not accumulated.

#### Would Kernel-Side Atomic Setup Prevent This?

**Partially—and more robustly.** A kernel module can set all five capability sets atomically in a single kernel operation. There is no accumulation of capability state across multiple userspace processes or exec() calls—the kernel module directly programs the task's `cred` structure before execve. There is no ambiguity about inheritance across "runc init" exec boundaries. More importantly, the kernel can enforce a strict interpretation of the capability sets from the spec without risking "leakage" through the complex Linux capability inheritance rules.

---

### 2.4 CVE-2016-9962 — runc ptrace of init via Shared FDs

**NVD**: "RunC allowed additional container processes via 'runc exec' to be ptraced by the pid 1 of the container. This allows the main processes of the container, if running as root, to gain access to file-descriptors of these new processes during the initialization and can lead to container escapes or modification of runC state before the process is fully placed inside the container."

#### Root Cause

When `runc exec` creates a new process to join a running container, the new process:
1. Is visible in the container's PID namespace immediately after fork
2. Has not yet completed namespace setup or capability dropping
3. Has an open fd to the "init pipe" containing sensitive container configuration
4. Has `PR_DUMPABLE` set (because execve resets it to 1), allowing `/proc/<pid>/fd` to be read by processes with `ptrace(2)` permission

A container's PID 1 running as root inside the container could:
- `ptrace(PTRACE_ATTACH, new_pid)` during the window between fork and namespace setup completion
- Read the new process's init pipe fd (via `ptrace` or `/proc/<pid>/fd/<N>`) to get the container configuration
- Modify the new process's state before security constraints are applied

#### runc's Fix

The nsexec.c code explicitly comments:
```c
/*
 * Make the process non-dumpable, to avoid various race conditions that
 * could cause processes in namespaces we're joining to access host
 * resources (or potentially execute code).
 */
if (config.namespaces) {
    write_log(DEBUG, "set process as non-dumpable");
    if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0)
        bail("failed to set process as non-dumpable");
}
```
`opencontainers/runc:libcontainer/nsenter/nsexec.c` (SHA 59b785, line ~380)

And `standard_init_linux.go` documents the O_PATH fifo close:
```go
// Close the O_PATH fifofd fd before exec because the kernel resets
// dumpable in the wrong order. This has been fixed in newer kernels, but
// we keep this to ensure CVE-2016-9962 doesn't re-emerge on older kernels.
// N.B. the core issue itself (passing dirfds to the host filesystem) has
// since been resolved.
// https://github.com/torvalds/linux/blob/v4.9/fs/exec.c#L1290-L1318
_ = fifoFile.Close()
```
`opencontainers/runc:libcontainer/standard_init_linux.go` (SHA 933c1d, ~line 200)

#### Would Kernel-Side Atomic Setup Prevent This?

**Yes, completely.** There is no intermediate process visible in the container's PID namespace during setup. The kernel module performs all setup on the task struct before it is made visible to other processes. The container process appears fully configured the moment it becomes observable.

---

### 2.5 youki/crun Analogues

**youki** (Rust OCI runtime): No unique CVEs have been published, but the runc advisory for CVE-2024-21626 explicitly notes that similar runtimes should check for `getcwd() != ENOENT` and consider `close_range(3, UINT_MAX, CLOSE_RANGE_CLOEXEC)`. youki's implementation mirrors runc's multi-stage setup and faces the same structural init-transition window.

**crun** (C OCI runtime): The same advisory notes: "crun 1.12 does not leak any useful file descriptors into the `runc init`-equivalent process (so this attack is *not exploitable* as far as we can tell), but no care is taken to make sure all non-stdio files are `O_CLOEXEC`." crun's lower attack surface comes from being written in C (no Go runtime fd management), but it still has the same structural init process that can be targeted.

**CVE-2023-27561** (runc): AppArmor/SELinux bypass when `/proc` inside the container is a symlink with a specific mount configuration. Fixed in runc v1.1.5 by prohibiting symlinked `/proc`. Advisory: https://github.com/opencontainers/runc/security/advisories/GHSA-g2j6-57v7-gm8c — demonstrates that LSM label application is vulnerable to container filesystem manipulation if it occurs after the container rootfs is live.

---

## 3. The Security-Critical Ordering

The following ordering is verified directly from `libcontainer/standard_init_linux.go` (opencontainers/runc SHA 933c1d) — this is the authoritative runc implementation:

```
standard_init_linux.go linuxStandardInit.Init() — exact sequence:

 1. [NS setup via nsexec.c, BEFORE Go runtime starts]
    – clone(CLONE_NEWPID|CLONE_NEWNS|CLONE_NEWUSER|CLONE_NEWNET|...)
    – Write /proc/<pid>/uid_map, /proc/<pid>/gid_map  (user NS)
    – PR_SET_DUMPABLE=0  [CVE-2016-9962 mitigation]
    – unshare(remaining flags)
    – Wait for grandchild (stage-2 init process)

 2. Session keyring setup (selinux.SetKeyLabel if ProcessLabel set)
 3. setupNetwork()  — configure veth pairs etc.
 4. setupRoute()
 5. selinux.GetEnabled()  — initialize labeling subsystem
 6. prepareRootfs()  — bind mounts, overlay, devpts, proc, sysfs
    ↳ includes procMount, maskDevices, mountCgroups, etc.
 7. setupConsole() if needed (before finalizing rootfs)
 8. setupPidfd()  — pidfd_open, send to parent (pidfd race-free)
 9. finalizeRootfs() → pivot_root()   ← MUST happen before priv drops
10. sethostname(), setdomainname()
11. apparmor.ApplyProfile()            ← LSM BEFORE no_new_privs
12. WriteSysctls()
13. readonlyPath()  — bind-mount readonly
14. maskPaths()  — bind-mount /proc/kcore, /proc/sysrq-trigger, etc. to /dev/null
15. PR_SET_NO_NEW_PRIVS=1  (if config.NoNewPrivileges)
    ← MUST happen before seccomp when seccomp needs NNP, not CAP_SYS_ADMIN
16. setupScheduler(), setupIOPriority(), setupPersonality(), setupMemoryPolicy()
17. syncParentReady()  ← last parent communication before exec
18. selinux.SetExecLabel()  ← SELinux applied at execve time
19. [IF NOT no_new_privs]: seccomp.InitSeccomp()  ← BEFORE capability drop
    ← requires CAP_SYS_ADMIN; applied before dropping caps in step 20
20. finalizeNamespace():
    a. utils.CloseExecFrom(N+3)  ← close leaked fds  [CVE-2024-21626]
    b. unix.Chdir(cwd)  ← first attempt as runc user
    c. w.ApplyBoundingSet()  ← cap bounding set BEFORE setuid
       ← MUST have CAP_SETPCAP to reduce bounding set; lose it after setuid
    d. system.SetKeepCaps()  ← PR_SET_KEEPCAPS=1  preserve across uid change
    e. setupUser() → unix.Setgroups(), unix.Setgid(), unix.Setuid()
       ← After this call, process is no longer root
    f. unix.Chdir(cwd)  ← second attempt as container user
    g. verifyCwd()  ← getcwd() == ENOENT → error  [CVE-2024-21626]
    h. system.ClearKeepCaps()  ← PR_SET_KEEPCAPS=0
    i. w.ApplyCaps()  ← set effective+permitted+inheritable+bounding+ambient
       ← final capability state
21. pdeath.Restore()  ← restore parent-death signal (cleared by setuid)
22. Check unix.Getppid() == l.parentPid  [CVE-2016-9962 protection]
23. exec.LookPath(args[0])  ← verify binary exists
24. [IF no_new_privs]: seccomp.InitSeccomp()  ← AS LATE AS POSSIBLE
    ← "Set seccomp as close to execve as possible, so as few syscalls
       take place afterward (reducing the amount of syscalls that users
       need to enable in their seccomp profiles)"
    ← Requires no_new_privs (set in step 15); no CAP_SYS_ADMIN needed
25. Close pipes/sockets
26. Open exec FIFO (block until parent unblocks)
27. utils.UnsafeCloseFrom(N+3)  ← final fd cleanup  [CVE-2024-21626]
28. linux.Exec(name, args, env)  ← execve — point of no return
```

### Why Each Ordering Constraint Is Security-Critical

**`pivot_root` (step 9) before LSM labels and readonly/mask paths (steps 11-14):**  
You need to be inside the container's mount namespace and have the container rootfs as the filesystem root before masking `/proc/kcore` or making paths readonly. Otherwise you'd be masking the *host* paths. Also, `pivot_root` requires `CAP_SYS_ADMIN` on the new root, which is dropped in step 20e. The kernel enforces: "The calling process must have CAP_SYS_ADMIN capability" (mount(2) man page).

**`pivot_root` before AppArmor profile (step 11):**  
An AppArmor profile is applied to the process label, not to paths. However, it must be applied *after* the container's rootfs is live (so the profile's path rules match the container's view). CVE-2023-27561 shows that a symlinked `/proc` could bypass AppArmor if the profile is applied before proc is properly mounted.

**`PR_SET_NO_NEW_PRIVS` (step 15) before seccomp (step 24, NNP path):**  
The kernel enforces this explicitly. From `seccomp(2)` man page: "In order to use the `SECCOMP_SET_MODE_FILTER` operation, either the calling thread must have the `CAP_SYS_ADMIN` capability in its user namespace, or the thread must already have the *no_new_privs* bit set. If that bit was not already set by an ancestor of this thread, the thread must make the following call: `prctl(PR_SET_NO_NEW_PRIVS, 1)`. Otherwise, the `SECCOMP_SET_MODE_FILTER` operation fails and returns `EACCES`."  
Source: https://man7.org/linux/man-pages/man2/seccomp.2.html

**Seccomp timing—the two paths (steps 19 vs. 24):**  
This is the most subtle ordering constraint. The runc comment explains it precisely:

```go
// Without NoNewPrivileges seccomp is a privileged operation, so we need to
// do this before dropping capabilities; otherwise do it as late as possible
// just before execve so as few syscalls take place after it as possible.
if l.config.Config.Seccomp != nil && !l.config.NoNewPrivileges {
    seccompFd, err := seccomp.InitSeccomp(l.config.Config.Seccomp)
    ...
}
```
`opencontainers/runc:libcontainer/standard_init_linux.go` (SHA 933c1d)

- **Without NNP**: seccomp needs `CAP_SYS_ADMIN`. It MUST be applied before step 20 drops capabilities. (Step 19, before finalizeNamespace.)
- **With NNP**: seccomp does NOT need `CAP_SYS_ADMIN`. It should be applied as late as possible (step 24, after capability drops) to minimize the set of post-seccomp syscalls the container operator must whitelist.

**`ApplyBoundingSet()` (step 20c) before `setuid()` (step 20e):**  
`CAP_SETPCAP` is required to reduce the bounding set. This capability exists only while the process is privileged. Once `setuid()` transitions to the container UID, the process loses `CAP_SETPCAP` (unless preserved by keepcaps—but keepcaps does not preserve bounding set operations). The bounding set must be fixed *before* the uid change. Source: `capabilities(7)` man page: "CAP_SETPCAP: ...Modify the calling thread's capability bounding set."

**`SetKeepCaps()` (step 20d) before `setuid()` (step 20e) before `ApplyCaps()` (step 20i):**  
Linux normally clears all capabilities when a process transitions from uid 0 to non-zero uid via `setuid(2)`. `PR_SET_KEEPCAPS` prevents this clearing of the *permitted* set. Without it, `setuid()` to a non-root UID would clear permitted capabilities, and `ApplyCaps()` could not restore them. The sequence is: set keepcaps → setuid → clear keepcaps → apply final caps. Source: `capabilities(7)`: "If the calling thread has a non-zero UID, then...its permitted capability set is cleared unless the thread's keepcaps flag is set."

**`selinux.SetExecLabel()` (step 18) applied at execve:**  
SELinux process labels are stored as exec-time transitions. `setexeccon()` (which calls `prctl(PR_SET_MM, ...)` or writes to `/proc/self/attr/exec`) sets a label that will be applied to the process's security context at the next `execve(2)`. It must be called before execve. Unlike AppArmor (which applies immediately), SELinux exec labels are "sticky" to the next exec.

**`UnsafeCloseFrom()` (step 27) must be the absolute last operation before execve:**  
After this call, all Go `*os.File` handles are invalidated. The comment is explicit: "we must not do any file operations after this point (otherwise the (*os.File) finaliser could close the wrong file). See CVE-2024-21626."

---

## 4. Kernel vs. Userspace: Where Each Step Belongs

### 4.1 What MUST Stay in Userspace (Attack Surface Reduction)

**Complex/untrusted parsing (config.json, image layers):**  
OCI `config.json` is untrusted input (potentially attacker-controlled via image registries). It contains nested JSON with arbitrary strings for mount sources, paths, environment variables, etc. Parsing this in the kernel would mean: every JSON parsing bug → kernel privilege escalation. This is the opposite of defense-in-depth. The config parser runs as an unprivileged daemon (containerd, CRI-O) and produces a well-validated, structured representation. The kernel module should receive only **verified, typed parameters**—not raw JSON.

Image layer assembly (overlayfs setup, bind mounts from image layers) involves walking untrusted directory trees, resolving symlinks, checking permissions across hundreds of files. This must stay in userspace where a bug causes at worst container-to-host isolation failure, not kernel RCE.

**Network configuration (CNI):**  
CNI plugins are complex userspace programs that create veth pairs, configure bridges, set up iptables/nftables rules, configure IPAM, etc. They run with `CAP_NET_ADMIN` as a separate process. The kernel enforces the network rules; the CNI plugin is just configuration. A bug in CNI → network misconfiguration, not kernel escalation.

**Cgroup configuration:**  
The container runtime creates cgroup directories under `/sys/fs/cgroup/<container-id>/`, writes resource limits to control files, etc. This is done *before* the container process starts. The kernel enforces the limits; the OCI runtime is just writing to cgroupfs. The key improvement is using `CLONE_INTO_CGROUP` (described below) to atomically place the container process into the pre-configured cgroup at fork time, eliminating the race between fork and cgroup assignment.

### 4.2 What Should Be Performed Atomically in Kernel Context

**The thesis:** runc's init-transition creates a vulnerable intermediate state where a userspace process (`runc init`) simultaneously holds: (a) membership in the container's namespaces; (b) elevated privileges (CAP_SYS_ADMIN); (c) live file descriptors to host resources; (d) a visible PID in both namespaces. No amount of patching fully eliminates this window.

A Rust kernel module can instead:

1. **Receive a validated, typed parameter block** from a privileged parent (or from the kernel module's own ioctl interface): capability sets, seccomp BPF program, UID/GID mappings, mount namespace fd, cgroup fd, binary path + argv + envp.

2. **Fork/clone with all namespace flags atomically:**
   - `clone3()` with `CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWNET | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWUSER | CLONE_INTO_CGROUP | CLONE_PIDFD`
   - The cgroup field in `clone_args` places the child in the configured cgroup **at fork time** (Linux 5.7, kernel commit f5d39b0)

3. **In the child context (kernel space), before the first userspace instruction:**
   - Write uid_map/gid_map (can be done from parent via the already-mapped userns)
   - `pivot_root()` — switch to container rootfs
   - Install seccomp filter via `seccomp(SECCOMP_SET_MODE_FILTER)` 
   - Set `PR_SET_NO_NEW_PRIVS`
   - Set capability bounding set via `cap_set_proc()`
   - `setgroups()`, `setgid()`, `setuid()`
   - Set final effective/permitted/inheritable caps
   - Apply LSM exec label
   - `execve()` — first userspace instruction is the container payload

**Why this is atomic from the security perspective:** There is no moment when an intermediate process is observable by anyone inside the container. The container process either doesn't exist yet (kernel is in `do_fork()`) or is fully configured. The `CLONE_PIDFD` flag means the parent gets a race-free pidfd to the child without ever exposing a PID that could be raced.

**No TOCTOU window:** In runc, there is a window between "runc init joins the mount namespace" and "runc init calls pivot_root" during which the process has a hybrid filesystem view. In a kernel module, `pivot_root()` can be called before the process ever executes a single userspace instruction.

**No fd leak window:** The kernel never passes internal fds through exec. The container process's fd table is constructed precisely: stdin/stdout/stderr plus any explicitly passed fds. No cgroup fd, no sync pipe, no log pipe.

**Closes the ptrace window (CVE-2016-9962):** The process is never in a partially-configured state visible to container-internal ptracers. When it appears in the container's PID namespace, it is already fully sandboxed.

---

## 5. seccomp BPF Specification

### 5.1 Data Structures

From `seccomp(2)` man page (https://man7.org/linux/man-pages/man2/seccomp.2.html):

```c
/* The program structure passed to seccomp(SECCOMP_SET_MODE_FILTER, ...) */
struct sock_fprog {
    unsigned short      len;     /* Number of BPF instructions */
    struct sock_filter *filter;  /* Pointer to array */
};

/* One BPF instruction */
struct sock_filter {
    __u16 code;  /* Actual filter code (BPF opcode) */
    __u8  jt;    /* Jump-if-true offset */
    __u8  jf;    /* Jump-if-false offset */
    __u32 k;     /* Generic multiuse field (immediate / offset) */
};

/* The read-only data the BPF program operates on */
struct seccomp_data {
    int   nr;                    /* System call number */
    __u32 arch;                  /* AUDIT_ARCH_* value (from <linux/audit.h>) */
    __u64 instruction_pointer;   /* CPU instruction pointer */
    __u64 args[6];               /* Up to 6 syscall arguments */
};
```

The BPF program accesses `seccomp_data` using absolute load offsets. The first four bytes (offset 0) are `nr` (the syscall number); offset 4 is `arch`. **Critically**: a well-written seccomp filter MUST check `arch` first. On x86-64, both x86_64 and x32 ABIs share `AUDIT_ARCH_X86_64`, distinguished by bit 30 of the syscall number. Failing to check arch enables syscall number confusion attacks.

### 5.2 Installation Syscalls

```c
/* Old prctl interface (no flags, always available): */
prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &fprog);

/* New seccomp(2) syscall (since Linux 3.17, for flags support): */
syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog);
```

runc's `sysSeccompSetFilter()` uses both:
```go
if flags == 0 {
    err = unix.Prctl(unix.PR_SET_SECCOMP,
        unix.SECCOMP_MODE_FILTER,
        uintptr(unsafe.Pointer(&fprog)), 0, 0)
} else {
    fdptr, _, errno := unix.RawSyscall(unix.SYS_SECCOMP,
        uintptr(C.C_SET_MODE_FILTER),
        uintptr(flags), uintptr(unsafe.Pointer(&fprog)))
    ...
}
```
`opencontainers/runc:libcontainer/seccomp/patchbpf/enosys_linux.go` (SHA b9a0be)

### 5.3 SECCOMP_FILTER_FLAG_* Values and Kernel Versions

From runc's patchbpf (SHA b9a0be) and the seccomp(2) man page:

| Flag | Value | Linux | Purpose |
|---|---|---|---|
| `SECCOMP_FILTER_FLAG_TSYNC` | `1<<0` | 3.17 | Sync filter to all threads |
| `SECCOMP_FILTER_FLAG_LOG` | `1<<1` | 4.14 | Log all non-allow decisions |
| `SECCOMP_FILTER_FLAG_SPEC_ALLOW` | `1<<2` | 4.17 | Disable SSB Spectre mitigation |
| `SECCOMP_FILTER_FLAG_NEW_LISTENER` | `1<<3` | 5.0 | Return seccomp notification fd |
| `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV` | `1<<5` | 5.19 | Wait for notification handler before kill |

### 5.4 The no_new_privs Requirement

From the kernel docs (https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html):

> "The `no_new_privs` bit (since Linux 3.5) is a new, generic mechanism to make it safe for a process to modify its execution environment in a manner that persists across execve. Any task can set `no_new_privs`. Once the bit is set, it is inherited across fork, clone, and execve and cannot be unset. With `no_new_privs` set, `execve()` promises not to grant the privilege to do anything that could not have been done without the execve call. For example, the setuid and setgid bits will no longer change the uid or gid; file capabilities will not add to the permitted set."

For seccomp: "Filters installed for the seccomp mode 2 sandbox persist across execve and can change the behavior of newly-executed programs. Unprivileged users are therefore only allowed to install such filters if `no_new_privs` is set."

**Why this is critical for kernel-side setup:** The kernel module itself runs with `CAP_SYS_ADMIN`, so it can install seccomp filters without `no_new_privs`. However, for correct semantics (seccomp should not be removable by the container process), the kernel module should also set `no_new_privs` on the child process before exec. This ensures that the container process cannot exec a setuid binary to escape the seccomp filter: "no_new_privs guarantees that execve() will not grant the privilege to do anything that could not have been done without the execve call."

### 5.5 Return Values (decreasing precedence)

From `kernel.org/doc/html/latest/userspace-api/seccomp_filter.html`:

```
SECCOMP_RET_KILL_PROCESS  → Terminate entire process (Linux 4.14)
SECCOMP_RET_KILL_THREAD   → Terminate calling thread  
SECCOMP_RET_TRAP          → Deliver SIGSYS
SECCOMP_RET_ERRNO         → Return errno (lower 16 bits = errno code)
SECCOMP_RET_USER_NOTIF    → Send notification to userspace fd (Linux 5.0)
SECCOMP_RET_TRACE         → Notify ptrace tracer (WARNING: tracer can bypass)
SECCOMP_RET_LOG           → Allow + log (Linux 4.14)
SECCOMP_RET_ALLOW         → Allow syscall
```

Note on `SECCOMP_RET_TRACE`: "seccomp-based sandboxes MUST NOT allow use of ptrace, even of other sandboxed processes, without extreme care; ptracers can use this mechanism to escape." (kernel docs) This is directly relevant to containers that try to run a debugger inside.

---

## 6. Kernel Primitives That Enable Atomic Container Setup

### 6.1 `clone3()` — Linux 5.3

The extensible container-creation syscall. Key fields:

```c
struct clone_args {
    u64 flags;       /* CLONE_* flags */
    u64 pidfd;       /* Where to store PID file descriptor */
    u64 child_tid;   /* child TID (in child memory) */
    u64 parent_tid;  /* child TID (in parent memory) */
    u64 exit_signal; /* Signal on child exit */
    u64 stack;       /* Lowest byte of stack */
    u64 stack_size;  /* Stack size */
    u64 tls;         /* TLS location */
    u64 set_tid;     /* Pointer to pid_t array (Linux 5.5) */
    u64 set_tid_size;/* Array size */
    u64 cgroup;      /* Target cgroup fd (Linux 5.7, CLONE_INTO_CGROUP) */
};
```

Source: https://man7.org/linux/man-pages/man2/clone3.2.html

`clone3()` allows combining `CLONE_PIDFD` (race-free child handle) with `CLONE_INTO_CGROUP` in a single syscall. runc already uses `SysProcAttr.UseCgroupFD = true` and `SysProcAttr.CgroupFD` to leverage this:

```go
// prepareCgroupFD sets up p.cmd to use clone3 with CLONE_INTO_CGROUP
// to join cgroup early, in p.cmd.Start.
func (p *setnsProcess) prepareCgroupFD() (*os.File, error) {
    ...
    p.cmd.SysProcAttr.UseCgroupFD = true
    p.cmd.SysProcAttr.CgroupFD = int(fd.Fd())
    ...
}
```
`opencontainers/runc:libcontainer/process_linux.go` (SHA f77225, ~line 225)

### 6.2 `CLONE_INTO_CGROUP` — Linux 5.7

Eliminates the race between fork and cgroup assignment (previously: fork → write PID to `cgroup.procs` → brief moment child is in parent's cgroup). With `CLONE_INTO_CGROUP`, the child starts in the target cgroup from its first instruction.

Critical for resource control: Without this, a resource-hungry container process could briefly burst before cgroup limits take effect. With a kernel module, the cgroup fd is opened by the orchestrator and passed in; the module sets it in `clone_args.cgroup`.

### 6.3 `pidfd` — Linux 5.3 (pidfd_open), CLONE_PIDFD

`pidfd_open(2)` and the `CLONE_PIDFD` clone flag provide race-free process handles. A pidfd refers to a specific process (by its kernel identity, not PID), immune to PID recycling. Operations:
- `pidfd_send_signal()` — signal a process without PID races
- `pidfd_getfd()` — steal a fd from another process (used by runc for seccomp notify)
- `poll()/epoll()` on pidfd — wait for process termination without races

Source: https://man7.org/linux/man-pages/man2/pidfd_open.2.html

runc already uses `setupPidfd()` to create a pidfd of the init process and pass it to the parent:
```go
func setupPidfd(socket *os.File, initType string) error {
    pidFd, err := unix.PidfdOpen(os.Getpid(), 0)
    ...
    cmsg.SendRawFd(socket, initType, uintptr(pidFd))
}
```
`opencontainers/runc:libcontainer/init_linux.go` (SHA 6dad31)

### 6.4 `openat2()` — Linux 5.6

The security-hardened successor to `openat()`. Key security flags:

```c
struct open_how {
    u64 flags;   /* O_* flags */
    u64 mode;    /* mode for O_CREAT */
    u64 resolve; /* RESOLVE_* flags */
};
```

Relevant `resolve` flags:
- `RESOLVE_NO_MAGICLINKS` — disallow magic-link traversal (directly blocks CVE-2019-5736 style attacks; "In a containerized environment, a magic link inside /proc may refer to an object outside the container, and thus may provide a means to escape from the container")
- `RESOLVE_IN_ROOT` — treat dirfd as chroot root; absolute symlinks resolved relative to dirfd
- `RESOLVE_BENEATH` — disallow escaping above dirfd
- `RESOLVE_NO_SYMLINKS` — disallow symlink traversal entirely

Source: https://man7.org/linux/man-pages/man2/openat2.2.html

A kernel module can use `openat2()` with `RESOLVE_NO_MAGICLINKS` when opening paths during container setup, preventing any path that resolves through a procfs magic link.

### 6.5 New Mount API: `fsopen`/`fsmount`/`move_mount`/`mount_setattr` — Linux 5.2+

The fd-based mount API eliminates path-based TOCTOU races in mount operations:

```c
/* Old way: path-based, races possible */
mount("/dev/sdb1", "/container/mnt", "ext4", MS_RDONLY, NULL);

/* New way: fd-based, atomic and race-free */
fsfd = fsopen("ext4", FSOPEN_CLOEXEC);   // Linux 5.2
fsconfig(fsfd, FSCONFIG_SET_PATH, "source", "/dev/sdb1", AT_FDCWD);
fsconfig(fsfd, FSCONFIG_SET_FLAG, "ro", NULL, 0);
fsconfig(fsfd, FSCONFIG_CMD_CREATE, NULL, NULL, 0);
mntfd = fsmount(fsfd, FSMOUNT_CLOEXEC, MOUNT_ATTR_RELATIME);
move_mount(mntfd, "", AT_FDCWD, "/container/mnt", MOVE_MOUNT_F_EMPTY_PATH);
```

Source: https://man7.org/linux/man-pages/man2/fsopen.2.html

`mount_setattr()` (Linux 5.12) atomically changes attributes on an entire mount tree:
```c
struct mount_attr attr = {
    .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV,
};
mount_setattr(mntfd, "", AT_EMPTY_PATH | AT_RECURSIVE, &attr, sizeof(attr));
```

This is critical for container rootfs setup: a kernel module can build the entire mount tree using fds (no path races), then atomically mark it `MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV`, then do `pivot_root(2)`.

Source: https://man7.org/linux/man-pages/man2/mount_setattr.2.html

### 6.6 Landlock LSM — Linux 5.13

An unprivileged LSM that a process can apply to itself to restrict its filesystem and network access. Unlike AppArmor/SELinux (which require privileged setup), Landlock rules are created and applied by the process itself:

```c
ruleset_fd = landlock_create_ruleset(&ruleset_attr, sizeof(ruleset_attr), 0);
prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);  // Required
landlock_restrict_self(ruleset_fd, 0);
```

Source: https://www.kernel.org/doc/html/latest/userspace-api/landlock.html

Landlock inherits across fork/clone/execve, stacks with other LSMs, and cannot be removed once applied. For a kernel module: Landlock can be applied by the module before exec, using fd-based rules that don't require path-based TOCTOU. It provides fine-grained per-path access rights beyond what the mount tree structure alone can enforce.

### 6.7 No Mainline "Kernel Container Creation" Proposal

There is **no accepted mainline proposal** for a single `container_create()` syscall that combines namespace creation, mount setup, capability configuration, and exec atomically. The kernel community's approach has been to add better building blocks: `clone3`, `CLONE_INTO_CGROUP`, `pidfd`, `openat2`, the new mount API, `mount_setattr`, Landlock. These primitives are individually correct, but composing them into a secure container still requires userspace orchestration or—as this design proposes—a kernel module.

The closest published work: Christian Brauner (Linux kernel maintainer, now Ubuntu kernel team lead at Canonical) has driven most of the container-relevant kernel primitives (clone3, pidfd, CLONE_INTO_CGROUP, mount API, idmapped mounts). His work represents the kernel community's approach of "better building blocks" rather than a single container syscall.

**Idmapped mounts** (Linux 5.12, `MOUNT_ATTR_IDMAP` + user namespace fd): Allow a mount tree to have different UID/GID mappings than the underlying filesystem, critical for user-namespace containers with bind mounts. A kernel module can configure these atomically via `mount_setattr()`.

---

## 7. Architecture Recommendations

### What the Kernel Module Does (Atomically):

| Operation | Kernel Primitive | Notes |
|---|---|---|
| Fork with namespaces | `clone3(CLONE_NEWPID\|CLONE_NEWNS\|CLONE_NEWNET\|...\|CLONE_INTO_CGROUP\|CLONE_PIDFD)` | Atomically in cgroup, returns pidfd |
| UID/GID mapping | Write `/proc/<pid>/uid_map` from parent | Must happen before child uses userns |
| Mount rootfs | `fsopen`/`fsconfig`/`fsmount`/`move_mount` | Fd-based, no path races |
| `pivot_root` | `pivot_root(2)` on child | Before any privilege drop |
| Mask /proc paths | `move_mount` over /proc/kcore etc. | Bind to /dev/null fd |
| Readonly paths | `mount_setattr(MOUNT_ATTR_RDONLY)` | Recursive mount flag |
| Cap bounding set | `cap_set_proc()` | Before setuid |
| `no_new_privs` | `prctl(PR_SET_NO_NEW_PRIVS, 1)` | Before seccomp if unprivileged |
| seccomp filter | `seccomp(SECCOMP_SET_MODE_FILTER, ...)` | After NNP; as late as possible before exec |
| LSM label | AppArmor: `aa_change_onexec()`; SELinux: write `/proc/self/attr/exec` | Before execve |
| setgroups/setgid/setuid | `setgroups(2)`, `setgid(2)`, `setuid(2)` | After bounding set; SetKeepCaps around setuid |
| Final caps | `cap_set_proc()` all five sets | After setuid |
| `execve` | `execve(path, argv, envp)` | First userspace instruction = container payload |

### What Stays in Userspace (Pre-module):

| Operation | Who | Why |
|---|---|---|
| config.json parsing | OCI runtime (containerd/CRI-O) | Untrusted input; parsing bugs should not be kernel bugs |
| Image layer assembly | OCI runtime + overlay driver | Complex path ops; container-to-host isolation failure, not kernel RCE |
| Cgroup pre-configuration | OCI runtime | Writes resource limits to cgroupfs before `clone3` |
| Network (CNI plugins) | CNI as separate process | Complex policy; kernel enforces via netfilter/tc |
| Seccomp policy compilation | OCI runtime | Converts OCI seccomp spec → `sock_fprog`; passed as validated binary to kernel module |
| AppArmor/SELinux policy | System administrator | LSM policy loaded at boot or by privileged daemon |

---

## 8. Citation Index

| Reference | Source |
|---|---|
| CVE-2019-5736 NVD | https://nvd.nist.gov/vuln/detail/CVE-2019-5736 |
| CVE-2019-5736 disclosure | https://www.openwall.com/lists/oss-security/2019/02/11/2 |
| CVE-2024-21626 advisory | https://github.com/opencontainers/runc/security/advisories/GHSA-xr7r-f8xq-vfvv |
| CVE-2022-29162 advisory | https://github.com/opencontainers/runc/security/advisories/GHSA-f3fp-gc8g-vw66 |
| CVE-2016-9962 NVD | https://nvd.nist.gov/vuln/detail/CVE-2016-9962 |
| CVE-2023-27561 (AppArmor bypass) | https://github.com/opencontainers/runc/security/advisories/GHSA-g2j6-57v7-gm8c |
| `exeseal/cloned_binary_linux.go` | `opencontainers/runc:libcontainer/exeseal/cloned_binary_linux.go` (SHA a3c6e59) |
| `standard_init_linux.go` | `opencontainers/runc:libcontainer/standard_init_linux.go` (SHA 933c1d) |
| `init_linux.go` (finalizeNamespace, verifyCwd) | `opencontainers/runc:libcontainer/init_linux.go` (SHA 6dad31) |
| `capabilities.go` | `opencontainers/runc:libcontainer/capabilities/capabilities.go` (SHA 6ac6dc) |
| `seccomp_linux.go` | `opencontainers/runc:libcontainer/seccomp/seccomp_linux.go` (SHA 7b3805) |
| `patchbpf/enosys_linux.go` | `opencontainers/runc:libcontainer/seccomp/patchbpf/enosys_linux.go` (SHA b9a0be) |
| `nsenter/nsexec.c` | `opencontainers/runc:libcontainer/nsenter/nsexec.c` (SHA 59b785) |
| `process_linux.go` (CLONE_INTO_CGROUP) | `opencontainers/runc:libcontainer/process_linux.go` (SHA f77225) |
| seccomp(2) man page | https://man7.org/linux/man-pages/man2/seccomp.2.html |
| seccomp_filter kernel docs | https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html |
| no_new_privs kernel docs | https://www.kernel.org/doc/html/latest/userspace-api/no_new_privs.html |
| Landlock kernel docs | https://www.kernel.org/doc/html/latest/userspace-api/landlock.html |
| clone3/CLONE_INTO_CGROUP man page | https://man7.org/linux/man-pages/man2/clone3.2.html |
| openat2(2) man page | https://man7.org/linux/man-pages/man2/openat2.2.html |
| fsopen(2) man page | https://man7.org/linux/man-pages/man2/fsopen.2.html |
| mount_setattr(2) man page | https://man7.org/linux/man-pages/man2/mount_setattr.2.html |
| pidfd_open(2) man page | https://man7.org/linux/man-pages/man2/pidfd_open.2.html |
| Landlock(7) man page | https://man7.org/linux/man-pages/man7/landlock.7.html |

---

## 9. Gaps and Uncertainties

1. **youki-specific CVEs**: youki's security advisories page is not publicly accessible at time of research. youki mirrors runc's structural init design and is subject to the same class of vulnerabilities; no unique published CVEs were found.

2. **crun detailed source**: crun's security advisory page requires authentication. The runc CVE-2024-21626 advisory explicitly analyzed crun 1.12 and found it not exploitable due to lower fd leakage, but this is version-specific.

3. **Kernel module `pivot_root` semantics**: `pivot_root(2)` in kernel context requires careful handling of the mount namespace. The new mount API (`move_mount` on a detached mount fd) may be preferable; the exact interaction between `fsmount()`-created detached mounts and `pivot_root()` in a new namespace warrants verification against kernel source (`fs/namespace.c`).

4. **`no_new_privs` and LSM interaction**: The kernel docs note: "LSMs might also not tighten constraints on exec in no_new_privs mode." This means AppArmor/SELinux exec transitions may not apply after NNP is set in some configurations. For the kernel module, applying LSM labels before NNP (or using the module's own CAP_SYS_ADMIN to apply them) sidesteps this issue entirely.

5. **Seccomp filter from kernel context**: The seccomp filter is compiled in userspace (libseccomp → `sock_fprog`), passed as a binary blob to the kernel module, and then installed via `seccomp(SECCOMP_SET_MODE_FILTER)` in kernel context. The kernel's BPF verifier will validate the filter. The security question is how the kernel module receives and validates the blob—it must be treated as trusted input from a privileged parent, not from the container image.