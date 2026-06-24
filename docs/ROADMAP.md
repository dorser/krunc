# krunc roadmap

The extensive plan to evolve krunc from the working v1 PoC into a robust,
all-Rust, OCI-integrated, mainline-credible **kernel workload/security-domain
object** (`krunc_domain`). Design: `docs/ARCHITECTURE.md`; threat model:
`docs/SECURITY.md`.

## Current direction: a self-contained, patch-free module
`krunc.ko` loads on an **unmodified kernel** — no vmlinux source patch, only a
vanilla `CONFIG_RUST=y` build (with `CONFIG_KPROBES` + `CONFIG_KALLSYMS_ALL`).
Two steps got us there:
- **DONE — drop seccomp + Landlock.** These were the only confinement layers that
  required in-tree kernel patches (they used file-static seccomp/Landlock helpers
  that a module cannot reach). They are removed; hardening is now done entirely
  from the module (namespaces, capability dropping, `no_new_privs`, in-kernel
  chroot + mounts, masked/read-only paths, cgroups). Active kill-on-escape is now
  provided by a patch-free **BPF-LSM** program attached at runtime; broader
  syscall/LSM-level hardening can build on that path without a kernel patch.
- **DONE — remove the `krunc_exports.c` vmlinux shim.** The internal symbols it
  exported/wrapped (`kernel_clone`, `kernel_execve`, `set_fs_root`, `path_mount`,
  `vfs_mkdir`, `do_exit`, cred/rlimit helpers, …) are now resolved at load time by
  a small C sibling module, `module/krunc_helper.c`, via a
  `kprobe → kallsyms_lookup_name` bootstrap. It re-exports thin `krunc_*` wrappers
  and is `insmod`ed before `krunc.ko`. Result: a self-contained pair of `.ko`s on
  a vanilla `CONFIG_RUST` kernel, no source patch.

**On the C helper and "patch-free":** the only requirements on the kernel are
*configuration* choices (`CONFIG_RUST`, `CONFIG_KPROBES`, `CONFIG_KALLSYMS_ALL`) —
never a source change. `krunc_helper.ko` is a loadable out-of-tree module, exactly
like `krunc.ko`; loading it is not patching the kernel. So the patch-free goal is
fully met. Folding the helper's generic primitives into Rust (so the module is one
language) is an *optional* code-uniformity refinement under the "All Rust"
principle below — not a patch-free requirement, and low priority.

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
  `mount_setattr`), `maskedPaths`, `readonlyPaths`, ro rootfs, `sysctl`.
  Host-side verification. `pivot_root` is deferred: on 6.18 only the syscall
  entry point takes `__user` pointers, with no callable in-kernel helper, and
  `root.readonly` now provides the immutable-rootfs benefit.
- **M4 — Privilege confinement.** Capability sets via `cred` lifecycle,
  `no_new_privs`, user (uid/gid/groups), rlimits, oomScoreAdj. Verify `CapEff`,
  `NoNewPrivs`, uid in `/proc/<pid>/status`.
- **M5 — seccomp.** Userspace compiles the OCI seccomp policy → `sock_filter[]`;
  the kernel installs it after `no_new_privs`. Verify a blocked syscall fails.
  *(Implemented, then REMOVED in the patch-free pivot — see "Current direction";
  it required an in-tree kernel patch. Active kill-on-escape is now via
  patch-free BPF-LSM; broader syscall policy remains future work.)*
- **M6 — cgroup v2.** `cgroupsPath` + resources (pids/memory/cpu); place the task
  in its cgroup atomically. Verify limit enforcement (fork-bomb/alloc capped).
- **M7 — Landlock seal.** Compile mounts/paths → a Landlock ruleset; seal the
  domain (fs + net + IPC scoping) before exec. Verify it is enforced and
  un-relaxable. *(Implemented, then REMOVED in the patch-free pivot — it required
  an in-tree kernel patch. Rootfs immutability is now provided by
  `root.readonly`; active kill-on-escape is now via patch-free BPF-LSM, with
  broader fs/path policy remaining future work.)*
- **M8 — Lifetime enforcement (Pillar 2) (done).** krunc now has a
  patch-free, per-container **BPF-LSM kill-on-escape** active response. A
  `BPF_PROG_TYPE_LSM` program (`bpf/krunc_lsm.bpf.c`) is attached at runtime to
  `lsm/file_open` and gated by a BPF hash map `guarded` keyed by cgroup id. For a
  task whose cgroup id is guarded, opening the demo tripwire basename
  `krunc-escape` calls `bpf_send_signal(SIGKILL)` and returns `-EPERM`, so the
  response kills and denies rather than passively denying. `bpf_get_current_cgroup_id()`
  scopes the policy to exactly the guarded container, not the host or other
  workloads. A small static libbpf loader (`bpf/krunc_lsm_loader.c`) loads and
  attaches the program, pins the link, and inserts the container cgroup id (the
  cgroup dir inode) between `krunc create` and `krunc start`, before the entrypoint
  executes. Kernel requirements remain config-only: `CONFIG_BPF_SYSCALL`,
  `CONFIG_BPF_LSM`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_FUNCTION_TRACER` →
  `CONFIG_DYNAMIC_FTRACE_WITH_DIRECT_CALLS`, `CONFIG_WERROR` off, with `bpf`
  already in the default `CONFIG_LSM` list. Reproduce with
  `KRUNC_BPF_LSM=1 scripts/build-kernel.sh`, then `scripts/build-bpf.sh` and
  `scripts/run-bpflsm.sh`. QEMU verification: PID 1 printed `alive`, was
  SIGKILL'd at tripwire `open(2)` before reading the file, `krunc state` showed
  `stopped`, and there was no kernel panic. Production integration would fold the
  loader into the CLI, preferably all-Rust via aya; the in-tree LSM remains the
  mainline form.
- **M9 — OCI conformance (partial — measured).** The official
  `opencontainers/runtime-tools` `runtimetest` validator runs as a container
  under krunc (harness: `scripts/qemu-conformance-init.sh` + `make-initramfs.sh`
  with `RUNTIMETEST=<binary>`). Against a config within krunc's supported subset it
  passes **237 of 249** MUST-level checks: hostname, cwd, env, `process.user`,
  capabilities (all five sets), rlimits, `oomScoreAdj`, `noNewPrivs`, namespaces,
  mounts, `maskedPaths`, `readonlyPaths` all conform. The **12 failures are all the
  OCI default `/dev` devices/symlinks** (`/dev/null`, `/dev/zero`, `/dev/full`,
  `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/ptmx` + `/dev/fd|stdin|stdout|
  stderr`), which krunc does not auto-create — a deliberate consequence of its
  strict "do exactly what's configured" stance (it also no longer auto-mounts the
  SHOULD default filesystems `/proc`,`/sys`). Whether to provide these
  runtime-supplied defaults is part of the strict-minimal-vs-spec-complete decision
  (see the deferred A/B/C fork). Mount options: krunc now implements the flag-based
  options the spec lists as MUST (`defaults`, `async`, `atime`, `dirsync`,
  `lazytime`, `iversion`, `loud`, …); the propagation options (`private`/`rprivate`/
  `rshared`/`rslave`) need a separate `mount(2)` propagation call krunc does not yet
  make, so they remain rejected (not silently dropped).
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
    BPF-LSM tripwire open (`krunc-escape`) kills + denies for the guarded cgroup;
    future coverage can add cgroupfs/release_agent write, cross-domain
    `setns`/ptrace, `open_by_handle_at` (Shocker), `core_pattern` write,
    syscall-class and path/connect probes
  - **tamper-proofness:** a workload with code-exec cannot relax seccomp/caps/
    Landlock (no_new_privs holds; bounding set holds; membership irreversible)
- **OCI conformance:** runtime-tools suite.
- **containerd:** `ctr run` e2e.
- A single `scripts/run-test.sh` runs the whole matrix in QEMU and reports.

## Honest scope
The **true** first-class domain (unprivileged, sealed, inherited, monotonic via
cred hooks) requires **in-tree** kernel changes — see `docs/ARCHITECTURE.md` §4.
The loadable-module track delivers the atomic setup (P1) and applies
no_new_privs/caps/cgroups/masked-readonly paths/root.readonly as a unified,
sealed domain enforced for life (P2), with BPF-LSM for active per-domain policy;
the in-tree LSM is the mainline graduation target. This roadmap is large and is
executed in verified increments, not in one shot.

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
  `tmpfs` `/tmp` mounted `nosuid,nodev,noexec`. **`root.readonly` is now done**:
  the module makes the mount tree private, bind-mounts the rootfs onto itself
  before chroot, then remounts `/` with `MS_REMOUNT|MS_BIND|MS_RDONLY`
  non-recursively after submount setup; it is fail-closed, and QEMU verified
  `touch /`→`EROFS` while `/tmp` stays writable. **`linux.sysctl` is now done**:
  the OCI layer validates names and values, emits `SYSCTLS` `relpath=value`
  entries, and the module writes `/proc/sys/<relpath>` before readonly-path
  remounts; QEMU verified `net.ipv4.ip_forward=1` in the container netns.
  `pivot_root` is deferred on 6.18 because only the syscall entry point exists
  (`__user` pointers, no callable in-kernel helper), and rootfs immutability is
  already achieved by `root.readonly`.
- **M6 (done) — cgroup v2.** The CLI creates the cgroup, sets limits, and places
  the container; the kernel enforces them. Three controllers, each verified
  deterministically: **pids** (`krunc-forktest` — `pids.current` pins at
  `pids.max=16`, the kernel denies further forks), **memory** (`krunc-memhog`
  — allocating past `memory.max=64 MiB` triggers the memcg OOM killer:
  `Memory cgroup out of memory: Killed process … (memhog)`, `memory.events
  oom_kill 1`), and **cpu** (`krunc-cpuhog` — a CPU-bound loop under
  `cpu.max=10000 100000` is throttled: `cpu.stat nr_throttled=69`). io is still
  to come.
- **M8 (done) — BPF-LSM kill-on-escape.** A runtime-attached
  `BPF_PROG_TYPE_LSM` program on `lsm/file_open`, keyed by cgroup id in the
  `guarded` map, kills the guarded container with `bpf_send_signal(SIGKILL)` and
  denies with `-EPERM` when it opens the `krunc-escape` tripwire. The static
  libbpf loader runs between `krunc create` and `krunc start`, pins the link, and
  inserts the cgroup id before PID 1 executes. It is patch-free with config-only
  BPF-LSM requirements (`KRUNC_BPF_LSM=1 scripts/build-kernel.sh`, then
  `scripts/build-bpf.sh` and `scripts/run-bpflsm.sh`) and was VM-verified: PID 1
  printed `alive`, was SIGKILL'd at `open(2)` before reading the file,
  `krunc state` showed `stopped`, and there was no kernel panic.
- **M5 (implemented, then REMOVED in the patch-free pivot) — seccomp.** The CLI
  compiled the OCI `linux.seccomp` policy into a
  classic-BPF `sock_filter[]` program (`krunc-oci::seccomp`, full x86-64 syscall
  table, 4 unit tests); the kernel installed it on the container **after**
  `no_new_privs`, in kernel context just before exec, via an in-tree helper
  (`krunc_seccomp_install` in `kernel/seccomp.c` + `krunc_bpf_prog_create_kern_trans`
  in `net/core/filter.c`, applied by `scripts/patch-kernel-seccomp.sh`). It was
  host-verified in QEMU (`chmod`→`EPERM`, `Seccomp: 2`). **This required an
  in-tree kernel patch, so it was removed in the patch-free pivot** (the helper,
  the patch script, and the compiler are gone; `linux.seccomp` is now rejected).
  Active kill-on-escape is now the patch-free BPF-LSM path; broader syscall/path
  policy remains future work.
- **M7 (implemented, then REMOVED in the patch-free pivot) — Landlock sealed fs domain.**
  When `root.readonly` was set, krunc
  derived a Landlock policy that handled the write/create/remove access rights but
  granted them only beneath the writable mounts (tmpfs/rw binds) plus `/dev`, and
  sealed it on the container via an in-tree helper (`krunc_landlock_restrict_writes`
  in `security/landlock/syscalls.c`, applied by `scripts/patch-kernel-seccomp.sh`),
  after `no_new_privs`, giving an **immutable rootfs with writable scratch**.
  Host-verified in QEMU (`touch /`→denied, `touch /tmp`→allowed). **This required
  an in-tree kernel patch, so it was removed in the patch-free pivot**; rootfs
  immutability is now enforced patch-free by `root.readonly` bind+remount-ro,
  active kill-on-escape is now enforced via patch-free BPF-LSM, while broader
  path-aware policy remains future work.
- **M10 — containerd integration (mechanism works; configs strictly gated).**
  krunc is runc-CLI-compatible, so containerd v2.3's `io.containerd.runc.v2` shim
  drives it (krunc as the runc binary), and the kernel-cloned init inherits the
  shim's stdio fifos. **However**, krunc is a *strict* runtime: per the
  runtime-spec `create` rule (a runtime MUST error on a property it cannot apply),
  it rejects configs carrying properties outside its supported subset. containerd's
  and nerdctl's default configs include a device cgroup (`linux.resources.devices`),
  so `ctr run`/`nerdctl run` with default configs can still be **rejected by
  design** (krunc refuses rather than silently dropping unsupported properties).
  `linux.sysctl` is now modeled and applied when valid; sysctl write failures are
  logged but non-fatal because a sysctl may be absent or non-namespaced.
  Containerd's and nerdctl's defaults also carry a `linux.seccomp` profile, which
  krunc now **rejects outright** (seccomp was removed in the patch-free pivot — it
  is no longer a modeled property). (Historically krunc did compile the moby/
  containerd default profile's `SCMP_CMP_EQ`/`SCMP_CMP_MASKED_EQ` argument matchers
  into real 64-bit BPF, after an earlier number-only-coarsening shortcut was
  reverted as a non-spec compromise; that whole seccomp path is now gone.)
  Running under containerd thus requires a reduced runtime config within krunc's
  subset, or implementing the remaining properties spec-faithfully (a future,
  in-spec item — e.g. the device cgroup). The CLI-rootfs prep (create mount
  destinations, PATH-resolve `argv[0]` per the spec's execvp semantics) remains.
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
  is prototyped; needs kernel-side `setsid`+`TIOCSCTTY`); M3 follow-up
  (`pivot_root` remains deferred); M7 user-ns id mapping; richer BPF-LSM policy
  beyond the VM-verified kill-on-escape; M9 conformance; a native Rust
  `containerd-shim-krunc-v2`; and the full `Domain` typestate object + domainfd.
