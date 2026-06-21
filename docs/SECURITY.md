# krunc security model

This document states krunc's threat model, the two security properties the
kernel-resident workload object provides, the enforcement substrate, and — most
importantly — the **honest limits**. It is grounded in the research under
`docs/research-notes/` (CVE analysis, kernel-API inventory, escape catalogue).

## 1. What krunc is (and is not)

krunc adds a **first-class kernel object — `krunc_domain`** — that represents a
workload after creation and enforces *sealed, monotonic, inherited* invariants on
its member tasks for the domain's entire lifetime. It is **not** a re-implementation
of OCI/containerd in the kernel (that stays in userspace), and it is **not**
VM-grade isolation.

Two properties, both delivered in kernel context:

- **P1 — Setup integrity:** a task enters-and-seals its domain atomically; there
  is *no* userspace "container init" process to hijack.
- **P2 — Lifetime confinement:** the kernel enforces the sealed invariants on
  every member for life; the policy is tamper-proof from inside the workload.

## 2. Threat model

- **Trusted:** the kernel, the krunc module/subsystem, and the privileged
  userspace runtime that *creates* a domain (it parses config and submits a
  validated spec).
- **Untrusted:** the workload's own code (the container payload), the container
  image/rootfs contents, and anything the workload can influence at runtime.
- **Goal:** even with full code-execution as (namespaced) root inside the
  workload, the workload cannot (a) subvert its own setup, (b) relax/escape its
  sealed domain, or (c) reach the host or other domains through the syscall/FS/
  IPC surface the domain forbids — and escape *attempts* are detectable and
  killable.
- **Explicit non-goal:** defeating an arbitrary kernel 0-day reachable through
  the *allowed* surface (see §6).

## 3. P1 — closing the setup window (the runc-init CVE class)

runc/youki/crun interpose a privileged `runc init` process that lives in a hybrid
state (partly in the container's namespaces, still holding host resources) before
exec'ing the payload. Essentially every container-runtime CVE exploits that
transition:

| CVE | Root cause | Why kernel-atomic setup closes it |
|---|---|---|
| CVE-2019-5736 | overwrite `/proc/self/exe` of `runc init` | no userspace init binary exists to overwrite; exec is from kernel context |
| CVE-2024-21626 | leaked host `/sys/fs/cgroup` fd + unchecked cwd through exec | fd table is managed in kernel and cleaned before the first container instruction; no intermediate cwd to race |
| CVE-2016-9962 | container pid 1 ptraces the still-initializing `runc exec` child via shared fds | no intermediate process is visible in the container pid ns during setup |
| CVE-2022-29162 | capability/inheritance leakage across init exec boundaries | all five cap sets programmed once into `cred` before exec, no cross-exec accumulation |
| CVE-2023-27561 / 2019-16884 | symlinked `/proc`, LSM label applied after rootfs is live | label/seccomp/caps applied before the untrusted rootfs is ever executed |

krunc performs the whole sequence as one kernel-context operation, in the
security-critical order (verified against runc `standard_init_linux.go`):

```
clone(new namespaces, no CLONE_VM)
 → uid/gid maps
 → no_new_privs = 1
 → mounts (new mount API) + pivot_root + mask/readonly paths + sysctls
 → capability bounding/effective/... sets
 → cgroup placement
 → rlimits, LSM label
 → setgroups/setgid/setuid (target user)
 → seccomp filter            (must be after no_new_privs)
 → Landlock restrict_self    (seal the fs/net/IPC domain)
 → kernel_execve(entrypoint)
```

Ordering is load-bearing: `no_new_privs` before seccomp (so a SUID payload can't
escape the filter); `pivot_root` before privilege drop (so the new root is
established while still privileged); label/seccomp/caps before the untrusted
rootfs runs.

### Implementation status (verified in QEMU vs. designed)

The pipeline above is the full design. What the current PoC **implements and
verifies from the host** (see `docs/sample-v2-confinement.txt`):

| Control | Status | Evidence (host-side) |
|---|---|---|
| New namespaces (no `CLONE_VM`), PID 1, UTS/mount/net | done | distinct ns inodes; `pid 1`; hostname |
| In-kernel private `/proc` + `/sys` | done | container reads `/proc` while fully confined |
| Capability bounding set + `no_new_privs` | done | `CapBnd=…200004e1`, `NoNewPrivs=1` |
| Effective/permitted/inheritable/ambient caps applied exactly | done | `CapEff=CapPrm=0` (only bounded, none granted) |
| rlimits + `oomScoreAdj` | done | `Max open files 256 512`; `oom_score_adj -500` |
| `process.user` uid/gid (runs as the requested non-root user) | done | `Uid: 65534`, `Gid: 65534` (host view) |
| `maskedPaths` + `readonlyPaths` | done | `/proc/kcore`→0 bytes; `/etc`,`/proc/sys` `EROFS` |
| seccomp (OCI→BPF, installed after `no_new_privs`) | done | `chmod`→`EPERM`; `Seccomp: 2` (filter) |
| cgroup v2 `pids` | done | kernel denies forks; `pids.current==pids.max` |
| cgroup v2 `memory` | done | memhog past `memory.max` → memcg OOM kill; `memory.events oom_kill 1` |
| `pivot_root` (replacing chroot) + `root.readonly` + general `mounts[]` | planned | (chroot-based read-only rootfs leaks the shared superblock; needs `pivot_root`) |
| user-ns uid/gid mapping | planned | — |
| Landlock seal + BPF-LSM active kill-on-escape | planned | — |

Everything marked *done* is applied **atomically in kernel context before the
first userspace instruction** and (for the sealed controls) holds for the
container's whole life.

## 4. P2 — lifetime confinement (post-setup escapes)

Setup integrity is necessary but not sufficient: the workload runs afterward and
will try to escape. The domain's invariants keep enforcing. The substrate is
composed entirely of **existing, proven, sealed/monotonic kernel mechanisms** that
the domain object *owns and applies atomically*:

- **seccomp** — continuous syscall filtering; **removes the entry point** for
  whole classes of kernel-exploit escapes (io_uring `CVE-2023-2598`, `bpf(2)`
  verifier bugs, exotic netfilter paths). Inherited across fork/exec, monotonic
  (filters only stack), and **tamper-proof under `no_new_privs`**.
- **capability bounding set** — `PR_CAPBSET_DROP` is monotonically decreasing; a
  workload can never re-grant a dropped capability. Drops `CAP_SYS_ADMIN`,
  `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH` (Shocker / `open_by_handle_at`), etc.
- **Landlock** — the closest existing analog to our object: a ruleset becomes a
  *sealed domain* attached to the task, **inherited across clone+execve**,
  **monotonic** ("can only be further restricted — never loosened"), un-relaxable
  from inside. Confines the filesystem, and (recent ABIs) network connect/bind
  and IPC scoping: `LANDLOCK_SCOPE_SIGNAL` (can't signal outside the domain) and
  `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` (blocks container→host abstract-socket
  IPC). Applicable before exec from kernel context.
- **cgroup v2** — resource limits (pids/memory/cpu) the kernel enforces
  continuously; closes fork-bomb / memory-exhaustion DoS.
- **masked/readonly paths + dropped sysctls + device confinement** — block the
  classic misconfig escapes: cgroup-v1 `release_agent`, `/proc/sys/kernel/
  core_pattern`, `/proc/sysrq-trigger`, writable `/sys`, `mknod` device access.

### Active per-domain policy + kill-on-escape
A loadable module **cannot** register native LSM hooks post-boot
(`security_add_hooks` is not exported; `DEFINE_LSM` lives in `__init`) — this is
intentional. The approved runtime mechanisms are:

- **BPF-LSM** (`CONFIG_BPF_LSM`, the stackable LSM): attach `BPF_PROG_TYPE_LSM`
  programs to hooks (`ptrace_access_check`, `sb_mount`, `move_mount`, `task_kill`,
  `bpf`, `socket_*`) keyed to the domain via `bpf_get_current_cgroup_id()`, and
  **kill on violation** via `bpf_send_signal(SIGKILL)` while returning `-EPERM`.
  This is the active-response path and the natural integration point for
  BPF-LSM-based runtime security (e.g. the author's micromize work).
- **Mainline form:** if krunc graduates, the domain object would be (or register)
  a **built-in LSM** so "may this task do X?" is answered natively by "which
  `krunc_domain` is it in?" — the FreeBSD `prison_check()` model.

So: the **PoC enforces P2 today via seccomp + cap bounding + cgroup +
masked/readonly paths** (all module-applicable, all sealed/monotonic), with
**Landlock** and a per-domain **BPF-LSM** kill-on-escape hook as the designed
next steps; the domain object is the **unifying owner** that applies them
atomically and ties them to one identity; **BPF-LSM** and a **built-in LSM** are
the active-response / mainline extensions.

## 5. Tamper-proofness

Once sealed, the domain cannot be widened from inside the workload:
- `no_new_privs` holds for life → no SUID/SGID privilege gain → seccomp/Landlock
  cannot be escaped via privilege escalation.
- seccomp filters and the capability bounding set are monotonic.
- Landlock has no `unrestrict_self`.
- domain membership is **irreversible and inherited** (like a FreeBSD jail and
  like Landlock domains) — a member cannot leave, and children join.
- there is **no userspace policy daemon** to kill; the guardian is the kernel.

## 6. Honest limits (stated plainly)

All containers — krunc included — share **one kernel**. A sufficiently powerful
kernel vulnerability reachable through the *allowed* syscall/FS surface can still
escape any namespace-based container. That is the axis where **gVisor**
(userspace kernel re-implementation) and **Kata Containers** (per-workload VM)
operate, at the cost of compatibility/performance.

krunc's P2 goal is therefore precise and bounded:
**defense-in-depth + a minimized, tamper-proof attack surface + active detection
and response** — *not* VM-grade isolation. Its strongest claims are: (1) it
removes the runc-init setup-escape class outright, and (2) it makes the workload's
confinement a sealed, kernel-owned, tamper-proof domain that also shrinks the
exploitable surface (seccomp) and can actively kill escape attempts (BPF-LSM).
Where stronger isolation is required, krunc composes with — rather than replaces —
VM/gVisor isolation.
