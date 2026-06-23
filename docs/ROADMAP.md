# krunc roadmap

The extensive plan to evolve krunc from the working v1 PoC into a robust,
all-Rust, OCI-integrated, mainline-credible **kernel workload/security-domain
object** (`krunc_domain`). Design: `docs/ARCHITECTURE.md`; threat model:
`docs/SECURITY.md`.

## Principles (non-negotiable)
- **All Rust.** The kernel module and the userspace adapter/CLI are Rust. (The
  v1 Go CLI + Go conformance tool are replaced.)
- **Idiomatic, minimal `unsafe`.** Every FFI is wrapped in a safe abstraction
  with a documented `# Safety` invariant; `#![deny(unsafe_op_in_unsafe_fn)]`.
  Use the type system as the correctness tool: newtypes (`DomainId`, `Pid`,
  `Uid`…), **typestate** for the domain lifecycle (`Unsealed`/`Sealed` so illegal
  transitions don't compile), RAII guards for kernel resources, no panics on the
  kernel path, bounded allocations with explicit GFP.
- **No JSON in the kernel.** Untrusted parsing stays in userspace; the kernel
  consumes a fixed, versioned, bounds-checked binary spec.
- **Verify everything** on the disposable Azure VM under QEMU/KVM; commit only
  green increments.

## Milestones
Each is independently verifiable and committed.

- **M0 — Design (done).** Research (`docs/research-notes/`), architecture,
  security model, ABI sketch, this roadmap.
- **M1 — All-Rust userspace adapter.** Replace `cli/` (Go) with an idiomatic Rust
  CLI: `oci-spec`/serde for `config.json`, `clap`, `nix`. create/start/state/
  kill/delete/list/features/--version with runc-compatible behavior. Unit +
  golden tests (config.json → binary spec) + `assert_cmd` integration. ABI parity
  with the module.
- **M2 — Module refactor + `Domain` object.** Introduce `Domain<Unsealed/Sealed>`
  typestate, the fd/id handle (`domainfd` via anon inode), a safe `ffi` module,
  proper sync (replace the `msleep` gate with `Completion`), a rich error enum,
  and a shared versioned ABI crate. Shrink the C shim to the minimal export set
  (or move in-tree). No behavior regression vs v1.
- **M3 — Filesystem confinement.** New mount API (`fsopen`/`fsmount`/`move_mount`/
  `mount_setattr`), `pivot_root` (replacing chroot), `maskedPaths`,
  `readonlyPaths`, ro rootfs, `sysctl`. Host-side verification.
- **M4 — Privilege confinement.** Capability sets via `cred` lifecycle,
  `no_new_privs`, user (uid/gid/groups), rlimits, oomScoreAdj. Verify `CapEff`,
  `NoNewPrivs`, uid in `/proc/<pid>/status`.
- **M5 — seccomp.** Userspace compiles the OCI seccomp policy → `sock_filter[]`;
  the kernel installs it after `no_new_privs`. Verify a blocked syscall fails.
- **M6 — cgroup v2.** `cgroupsPath` + resources (pids/memory/cpu); place the task
  in its cgroup atomically. Verify limit enforcement (fork-bomb/alloc capped).
- **M7 — Landlock seal.** Compile mounts/paths → a Landlock ruleset; seal the
  domain (fs + net + IPC scoping) before exec. Verify it is enforced and
  un-relaxable.
- **M8 — Lifetime enforcement (Pillar 2).** Wire the domain as the unifying owner
  of the above; design + prototype the BPF-LSM per-domain policy + kill-on-escape
  path; document the in-tree LSM (Landlock-extended) as the mainline form.
- **M9 — OCI conformance.** Run `opencontainers/runtime-tools` validation against
  the Rust CLI; green for supported features; precisely report the unsupported.
- **M10 (done — see below) — containerd e2e.** Real containerd + offline busybox
  OCI image + krunc runtime; `ctr run` and `nerdctl run`. A native Rust
  `containerd-shim-krunc-v2` remains optional future work.
- **M11 — Hardening + docs.** Fuzz the ABI validator; stress/soak; finalize
  SECURITY/ARCHITECTURE and the mainline-graduation (in-tree LSM) write-up.

## Verification strategy
- **CLI:** `cargo test` unit + golden (config.json→spec) + `assert_cmd`.
- **ABI:** property round-trip tests; fuzz the kernel-side validator via a
  userspace harness that compiles the parser as a lib.
- **Integration (QEMU):** a test runner asserting confinement **from the host
  side** for each feature:
  - ns inodes differ; hostname; pid 1; uid/gid; `NoNewPrivs=1`
  - `CapEff` is the reduced set
  - seccomp: a probe calling a blocked syscall gets the expected errno/kill
  - ro rootfs write fails; masked path reads empty/denied
  - cgroup limits enforced (fork-bomb / allocation capped)
  - **post-setup escape attempts are denied/killed** while benign ops continue:
    cgroupfs/release_agent write, cross-domain `setns`/ptrace,
    `open_by_handle_at` (Shocker), `core_pattern` write, a seccomp-blocked
    exploit-class syscall, a Landlock-denied path/connect
  - **tamper-proofness:** a workload with code-exec cannot relax seccomp/caps/
    Landlock (no_new_privs holds; bounding set holds; membership irreversible)
- **OCI conformance:** runtime-tools suite.
- **containerd:** `ctr run` e2e.
- A single `scripts/run-test.sh` runs the whole matrix in QEMU and reports.

## Honest scope
The **true** first-class domain (unprivileged, sealed, inherited, monotonic via
cred hooks) requires **in-tree** kernel changes — see `docs/ARCHITECTURE.md` §4.
The loadable-module track delivers the atomic setup (P1) and applies
seccomp/caps/Landlock/cgroup as a unified, sealed domain enforced for life (P2),
with BPF-LSM for active per-domain policy; the in-tree LSM is the mainline
graduation target. This roadmap is large and is executed in verified increments,
not in one shot.

## Status
- M0 (design) done. v1 PoC is the working foundation.
- **M1 done** — all-Rust userspace: `krunc-abi` (13 tests), `krunc-oci` (11 tests),
  `krunc-cli` (static musl binary). The Go CLI/conformance tool were removed.
- **M2 (partial) done** — the kernel consumes the versioned **binary** ABI
  (strict, bounds-checked, no JSON in kernel); two-phase create/start. (The full
  `Domain` typestate object + `domainfd` handle are still to come.)
- **M4 (done) — privilege confinement.** The kernel applies the **five capability
  sets + `no_new_privs`** atomically before exec, plus **rlimits and
  `oomScoreAdj`**. Each capability set is applied *exactly* as the OCI config
  specifies — effective/permitted/inheritable/ambient default to empty rather
  than silently equalling the bounding set. Host-verified in QEMU: the OCI
  container shows `CapBnd=00000000200004e1` (6 bounded) with
  `CapEff=CapPrm=0` (none granted) and `NoNewPrivs=1`, vs `000001ffffffffff`/`0`
  for the unconfined text container; `RLIMIT_NOFILE=256/512` and
  `oom_score_adj=-500` confirmed via `/proc/<pid>/{limits,oom_score_adj}`, and
  the OCI container runs as the requested non-root user (`Uid/Gid 65534`). See
  `docs/sample-v2-confinement.txt`.
- **M3 (partial) done** — the kernel mounts a private `/proc` + `/sys` for the
  container in-kernel (via `path_mount`) before dropping privileges, so even a
  confined container has them. **maskedPaths + readonlyPaths** are now also
  enforced in-kernel: each masked path is over-mounted (bind `/dev/null` for
  files, read-only `tmpfs` for dirs) and each read-only path is bind-mounted then
  remounted `MS_RDONLY`, all in the container's mount namespace before exec.
  Host-verified in QEMU: `/proc/kcore` reads 0 bytes, `/proc/sysrq-trigger`
  writes are inert, and writes to `/etc` and `/proc/sys` fail with `EROFS`.
  The kernel also performs the bundle's **`mounts[]`** (in order, replacing the
  hard-coded default), translating OCI options to `MS_*` flags — verified by a
  `tmpfs` `/tmp` mounted `nosuid,nodev,noexec`. (Full `pivot_root` + `root.readonly`
  and sysctls are still to come.)
- **M6 (done) — cgroup v2.** The CLI creates the cgroup, sets limits, and places
  the container; the kernel enforces them. Three controllers, each verified
  deterministically: **pids** (`krunc-forktest` — `pids.current` pins at
  `pids.max=16`, the kernel denies further forks), **memory** (`krunc-memhog`
  — allocating past `memory.max=64 MiB` triggers the memcg OOM killer:
  `Memory cgroup out of memory: Killed process … (memhog)`, `memory.events
  oom_kill 1`), and **cpu** (`krunc-cpuhog` — a CPU-bound loop under
  `cpu.max=10000 100000` is throttled: `cpu.stat nr_throttled=69`). io is still
  to come.
- **M5 (done) — seccomp.** The CLI compiles the OCI `linux.seccomp` policy into a
  classic-BPF `sock_filter[]` program (`krunc-oci::seccomp`, full x86-64 syscall
  table, 4 unit tests); the kernel installs it on the container **after**
  `no_new_privs`, in kernel context just before exec, via an in-tree helper
  (`krunc_seccomp_install` in `kernel/seccomp.c` + `krunc_bpf_prog_create_kern_trans`
  in `net/core/filter.c`, applied by `scripts/patch-kernel-seccomp.sh`). Because
  it is sealed under `no_new_privs`, a compromised workload cannot relax it.
  Host-verified in QEMU: a `chmod` (needs no capability on an owned path) returns
  `EPERM`, and `/proc/<pid>/status` shows `Seccomp: 2` (filter mode), with no
  kernel warnings.
- **M7 (done) — Landlock sealed fs domain.** When `root.readonly` is set, krunc
  derives a Landlock policy that handles the write/create/remove access rights but
  grants them only beneath the writable mounts (tmpfs/rw binds) plus `/dev`, and
  seals it on the container via an in-tree helper (`krunc_landlock_restrict_writes`
  in `security/landlock/syscalls.c`, applied by `scripts/patch-kernel-seccomp.sh`),
  after `no_new_privs`. Read/execute stay unrestricted, so the container has an
  **immutable rootfs with writable scratch** — the kernel's own sealed,
  inherited-across-exec, monotonic domain (the closest existing analog to the
  `krunc_domain` vision), and it achieves the immutability that a chroot-based
  `root.readonly` cannot. Host-verified in QEMU: the container's `touch /` is
  **denied**, `touch /tmp` is **allowed**.
- **M10 — containerd integration (mechanism works; configs strictly gated).**
  krunc is runc-CLI-compatible, so containerd v2.3's `io.containerd.runc.v2` shim
  drives it (krunc as the runc binary), and the kernel-cloned init inherits the
  shim's stdio fifos. **However**, krunc is a *strict* runtime: per the
  runtime-spec `create` rule (a runtime MUST error on a property it cannot apply),
  it rejects configs carrying properties outside its supported subset. containerd's
  and nerdctl's default configs include a device cgroup (`linux.resources.devices`)
  and `sysctls`, so `ctr run`/`nerdctl run` with default configs are **rejected by
  design** (krunc refuses rather than silently dropping those properties). An
  earlier shortcut that silently weakened the policy to make containerd "work"
  (coarsening seccomp argument matchers into a number-only filter) was reverted as
  a convention-driven, non-spec compromise; the spec-correct resolution shipped
  instead — krunc now compiles the equality argument matchers (`SCMP_CMP_EQ`,
  `SCMP_CMP_MASKED_EQ`, which is all the moby/containerd default profile uses) into
  real 64-bit BPF comparisons, so argument-matched seccomp is no longer a blocker.
  Running under containerd still requires a reduced runtime config within krunc's
  subset, or implementing the remaining properties spec-faithfully (a future,
  in-spec item — e.g. the device cgroup). The CLI-rootfs prep (create mount
  destinations, PATH-resolve `argv[0]` per the spec's execvp semantics) and the
  privileged-time seccomp install remain.
- **mounts (done) — full containerd mount set.** The kernel now materializes
  nested mountpoints (`krunc_mkdir` → `vfs_mkdir`) before each filesystem mount,
  so a stock containerd/nerdctl `/dev/pts`, `/dev/shm`, `/dev/mqueue`,
  `/sys/fs/cgroup`, … all mount inside the just-created `/dev` tmpfs (host-verified
  under `nerdctl run`). Non-tty stdio works; **interactive `-t` (console-socket
  PTY + controlling-terminal setup) is not yet wired** — use `--net none` and
  non-tty for now.
- **krunc run (done) — docker-style one-shot.** `krunc run [--image <name>|<name>]
  -- <cmd>` synthesizes a hardened bundle around an extracted rootfs and runs the
  command create+start+wait+delete, streaming output and propagating the exit
  code (host-verified: `krunc run busybox -- echo`, `CapEff/CapBnd 0`).
- **Next:** interactive `-t` console-socket support (PTY handoff via `SCM_RIGHTS`
  is prototyped; needs kernel-side `setsid`+`TIOCSCTTY`); M3 remainder
  (`pivot_root`, sysctls); M7 user-ns id mapping; M8 lifetime enforcement
  (BPF-LSM kill-on-escape); M9 conformance; a native Rust
  `containerd-shim-krunc-v2`; and the full `Domain` typestate object + domainfd.
