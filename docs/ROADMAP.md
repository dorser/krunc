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
- **M10 — containerd e2e.** Real containerd + offline busybox OCI image + krunc
  runtime; `ctr run`. Document results (incl. exit-notification via the shim
  subreaper). Optionally a native Rust `containerd-shim-krunc-v2`.
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
- M0 done. v1 PoC (3 commits) is the working foundation. M1+ pending build/test
  access (the Azure test VM under QEMU).
