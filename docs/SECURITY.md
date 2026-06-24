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

The current PoC is **patch-free**: it runs on a vanilla `CONFIG_RUST=y` kernel
plus `CONFIG_KPROBES` and `CONFIG_KALLSYMS_ALL`. `krunc_helper.ko` loads before
`krunc.ko`, resolves non-exported primitives through a kprobe→`kallsyms_lookup_name`
bootstrap, and exposes thin `krunc_*` wrappers to the Rust module.

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
| CVE-2023-27561 / 2019-16884 | symlinked `/proc`, LSM label applied after rootfs is live | caps/no_new_privs/domain controls applied before the untrusted rootfs is ever executed |

krunc performs the implemented subset as one kernel-context operation, in the
security-critical order (verified against runc `standard_init_linux.go`):

```
clone(new namespaces, no CLONE_VM)
 → no_new_privs = 1
 → rootfs setup (chroot; `pivot_root` deferred) + mounts + sysctls + root.readonly + mask/readonly paths
 → capability bounding/effective/... sets
 → cgroup placement
 → rlimits, oomScoreAdj
 → setgroups/setgid/setuid (target user)
 → kernel_execve(entrypoint)
```

Ordering is load-bearing: `no_new_privs` before privilege drop (so a SUID
payload can't gain privilege); rootfs setup before privilege drop; caps/cgroups/
rlimits before the untrusted rootfs runs. The removed seccomp/Landlock stages
required kernel source patches; the patch-free immutable rootfs is now enforced
by `root.readonly` bind+remount-ro, while active kill-on-escape is now
implemented via patch-free BPF-LSM.

### Implementation status (verified in QEMU vs. designed)

The pipeline above is the current patch-free flow; the full design adds the
remaining planned controls called out below. What the current PoC **implements
and verifies from the host/VM** (see `docs/sample-v2-confinement.txt` and the
BPF-LSM tripwire run):

| Control | Status | Evidence (host-side) |
|---|---|---|
| New namespaces (no `CLONE_VM`), PID 1, UTS/mount/net | done | distinct ns inodes; `pid 1`; hostname |
| In-kernel private `/proc` + `/sys` | done | container reads `/proc` while fully confined |
| Capability bounding set + `no_new_privs` | done | `CapBnd=…200004e1`, `NoNewPrivs=1` |
| Effective/permitted/inheritable/ambient caps applied exactly | done | `CapEff=CapPrm=0` (only bounded, none granted) |
| rlimits + `oomScoreAdj` | done | `Max open files 256 512`; `oom_score_adj -500` |
| `process.user` uid/gid (runs as the requested non-root user) | done | `Uid: 65534`, `Gid: 65534` (host view) |
| `maskedPaths` + `readonlyPaths` | done | `/proc/kcore`→0 bytes; `/etc`,`/proc/sys` `EROFS` |
| OCI `mounts[]` (config-driven, with `nosuid/nodev/noexec/ro`) | done | `/tmp` = `tmpfs rw,nosuid,nodev,noexec` |
| seccomp (OCI→BPF, installed after `no_new_privs`) | removed (required a kernel source patch) | configs with `linux.seccomp` are rejected; `Seccomp: 0` |
| **active kill-on-escape** (BPF-LSM replacement) | done | runtime-attached `BPF_PROG_TYPE_LSM` on `file_open`, cgroup-id-keyed `guarded` map, `bpf_send_signal(SIGKILL)`+`-EPERM`; guarded container SIGKILL'd at tripwire `open(2)`, never read the file, `krunc state`=`stopped` |
| cgroup v2 `pids` | done | kernel denies forks; `pids.current==pids.max` |
| cgroup v2 `memory` | done | memhog past `memory.max` → memcg OOM kill; `memory.events oom_kill 1` |
| cgroup v2 `cpu` | done | cpuhog under `cpu.max` throttled; `cpu.stat nr_throttled` climbs |
| `root.readonly` immutable rootfs | done | `touch /`→`EROFS`; `/tmp` writable; bind-mount rootfs + `MS_REMOUNT`&#124;`MS_BIND`&#124;`MS_RDONLY`, fail-closed |
| `linux.sysctl` | done | `net.ipv4.ip_forward`=1 in the container netns |
| `pivot_root` (replacing chroot) | deferred | immutability achieved via `root.readonly`; no callable in-kernel `pivot_root` on 6.18 |
| user-ns uid/gid mapping | planned | — |
| BPF-LSM richer path/mount/syscall policy | planned | extends the patch-free runtime LSM path beyond the VM-verified `file_open` tripwire |

Everything marked *done* is armed before the first container userspace
instruction (setup controls in kernel context; BPF-LSM between create/start) and
(for the sealed controls) holds for the container's whole life.

## 4. P2 — lifetime confinement (post-setup escapes)

Setup integrity is necessary but not sufficient: the workload runs afterward and
will try to escape. The domain's invariants keep enforcing. The substrate is
composed entirely of **existing, proven, sealed/monotonic kernel mechanisms** that
the domain object *owns and applies atomically*:

- **seccomp precedent (not used by the current PoC)** — the proven mainline model
  for sealed, inherited, monotonic syscall filtering under `no_new_privs`.
  krunc removed its seccomp implementation because a loadable module needed a
  kernel source patch for the required helpers; the BPF-LSM kill-on-escape hook is
  now the patch-free active replacement, with broader syscall/path/mount-aware
  policy still future work.
- **capability bounding set** — `PR_CAPBSET_DROP` is monotonically decreasing; a
  workload can never re-grant a dropped capability. Drops `CAP_SYS_ADMIN`,
  `CAP_SYS_MODULE`, `CAP_DAC_READ_SEARCH` (Shocker / `open_by_handle_at`), etc.
- **Landlock precedent (not used by the current PoC)** — the closest existing
  analog to our object: a ruleset becomes a *sealed domain* attached to the task,
  **inherited across clone+execve**, **monotonic** ("can only be further
  restricted — never loosened"), un-relaxable from inside. It remains the
  canonical model for `krunc_domain`; `root.readonly` now provides
  rootfs immutability and BPF-LSM now provides patch-free active kill-on-escape;
  broader path/mount-aware policy remains future work.
- **cgroup v2** — resource limits (pids/memory/cpu) the kernel enforces
  continuously; closes fork-bomb / memory-exhaustion DoS.
- **masked/readonly paths + modeled sysctls + device confinement** — block the
  classic misconfig escapes: cgroup-v1 `release_agent`, `/proc/sys/kernel/
  core_pattern`, `/proc/sysrq-trigger`, writable `/sys`, `mknod` device access.

### Active per-domain policy + kill-on-escape
A loadable module **cannot** register native LSM hooks post-boot
(`security_add_hooks` is not exported; `DEFINE_LSM` lives in `__init`) — this is
intentional. The approved runtime mechanisms are:

- **BPF-LSM** (`CONFIG_BPF_LSM`, the stackable LSM): krunc now attaches a
  `BPF_PROG_TYPE_LSM` program at runtime to `lsm/file_open`, keyed to the guarded
  container via `bpf_get_current_cgroup_id()` and a cgroup-id-keyed `guarded` map.
  Opening the demo tripwire basename `krunc-escape` calls
  `bpf_send_signal(SIGKILL)` and returns `-EPERM`, so this is an active response
  (kill + deny), not a passive deny. The static libbpf loader runs between
  `krunc create` and `krunc start`, pins the link, and inserts the cgroup id
  before the entrypoint executes. This is patch-free and config-only:
  `CONFIG_BPF_SYSCALL`, `CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF`,
  `CONFIG_FUNCTION_TRACER` → `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS`, and
  `CONFIG_WERROR` off; reproduce with `KRUNC_BPF_LSM=1 scripts/build-kernel.sh`,
  then `scripts/build-bpf.sh` and `scripts/run-bpflsm.sh`. QEMU verified the
  guarded container was SIGKILL'd at tripwire `open(2)`, never read the file,
  `krunc state` was `stopped`, and there was no kernel panic. Production should
  fold the loader into the CLI, preferably all-Rust via aya; richer hooks
  (`ptrace_access_check`, `sb_mount`, `move_mount`, `task_kill`, `bpf`,
  `socket_*`) remain natural extensions.
- **Mainline form:** if krunc graduates, the domain object would be (or register)
  a **built-in LSM** so "may this task do X?" is answered natively by "which
  `krunc_domain` is it in?" — the FreeBSD `prison_check()` model.

So: the **PoC enforces P2 today via no_new_privs + cap bounding + cgroup +
masked/readonly paths, rootfs read-only sealing, sysctl setup, and a per-domain
BPF-LSM kill-on-escape hook** (module-applicable/config-only, with monotonic
capability and resource limits plus active response); the domain object is the
**unifying owner** that applies them atomically and ties them to one identity. A
**built-in LSM** remains the mainline extension.

## 5. Tamper-proofness

Once sealed, the domain cannot be widened from inside the workload:
- `no_new_privs` holds for life → no SUID/SGID privilege gain.
- the capability bounding set is monotonic/irreversible.
- cgroup membership and limits are enforced by the kernel for member tasks.
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
exploitable surface (cap bounding, namespaces, cgroups, masked/readonly paths)
and now actively kills the VM-verified tripwire escape attempt via patch-free
BPF-LSM.
Where stronger isolation is required, krunc composes with — rather than replaces —
VM/gVisor isolation.
