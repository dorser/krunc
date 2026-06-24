# krunc architecture — a first-class kernel workload/security-domain object

> Status: design. The committed v1 PoC (a Rust module that creates containers in
> kernel context + a runc-compatible userspace adapter) is the working
> foundation; this document defines the v2 target — the **`krunc_domain`** object
> — and the path from one to the other. Grounded in `docs/research-notes/`.

## 1. The missing noun

A Linux "container" is *emergent*: a userspace runtime composes namespaces +
cgroups + capabilities + optional syscall/LSM policy, then exits. The kernel
never holds an object that says "*these tasks are workload X; this is its
security domain; enforce it for life.*" Contrast FreeBSD, where `struct prison`
(`sys/kern/kern_jail.c`) is a first-class object with:

- stable **identity** (`pr_id`) and **lifecycle** (`ALIVE → DYING`),
- **sealed, monotonic invariants** (allow-flags only tighten; no `jail_detach`),
- complete **inheritance** via `struct ucred.cr_prison`, copied on `fork()`,
- pervasive **enforcement** via `prison_check()` at every cross-process check.

Linux's `struct nsproxy` has none of these — no identity, no lifecycle, no sealed
invariants, no enforcement hook. The closest attempt, the **audit container ID**
(Richard Guy Briggs), was never merged. krunc adds the missing noun:
**`krunc_domain`**, a durable kernel object that represents the workload and
enforces sealed invariants on its members for life.

## 2. The object

```
krunc_domain {
    id          : u64            // stable identity (audit correlation)
    refcount    : atomic         // freed when last member exits
    parent      : Option<domain> // nestable, jail-style
    nsproxy     : *nsproxy        // the namespace set it owns (additive handle)
    cgroup      : cgroup ref      // membership + resource accounting substrate
    // sealed invariants (monotonic after seal):
    cap_ceiling : kernel_cap_t
    bpf_lsm     : runtime active policy hooks
    fs_net_ipc  : sealed access masks  (Landlock-modelled vision)
    rules       : mount/ptrace/setns/device policy
    state       : Unsealed | Sealed
}
```

- **Handle = an fd** (`domainfd`), following the Landlock/pidfd model
  (`anon_inode_getfd("[krunc-domain]", …)`). The fd is a stable reference: poll
  it for "all members exited," pass it to a monitor, `ioctl` it for the numeric
  id/membership. Strongly preferred over a global id (composes with Linux;
  lifecycle is automatic).
- **Additive, not a replacement.** The domain *references* an existing namespace
  set + cgroup; it does not reimplement them. It is the unifying handle +
  sealed-policy contract layered on top.

## 3. Lifecycle (typestate)

```
Unsealed  ──configure invariants──▶  Unsealed
Unsealed  ──seal()──────────────────▶  Sealed
Sealed    ──attach task / fork / exec──▶  member (inherited, irreversible)
Sealed    ──restrict further──────────▶  Sealed   (monotonic: only tightens)
last member exits ───────────────────▶  freed
```

Modelled exactly on Landlock's proven contract (`landlock_restrict_self`):
- `seal()`/`restrict_self(domainfd)` requires `no_new_privs` **or**
  `CAP_SYS_ADMIN`; it `prepare_creds()` → sets the domain on the new cred blob →
  `commit_creds()`. After commit the domain pointer is **immutable**; there is no
  `domain_escape()`/`relax()`.
- **fork inheritance**: the `cred_prepare` LSM hook copies the domain pointer and
  bumps its refcount — every child joins.
- **exec inheritance**: `bprm_committing_creds` retains the domain;
  `no_new_privs` blocks privilege-escalation paths that could shed it.

In Rust this is encoded as **typestate** (`Domain<Unsealed>` vs `Domain<Sealed>`)
so "configure after seal" or "double-seal" do not compile.

## 4. Enforcement substrate (all existing, sealed/monotonic primitives)

The domain object's value is that it **owns and applies these atomically as one
identity**, and the kernel can answer "may this task do X?" with "which domain is
it in?":

| Invariant | Mechanism | Properties |
|---|---|---|
| syscall surface | **seccomp** precedent; removed from PoC (required a kernel source patch) | mainline model for inherited, monotonic filtering; BPF-LSM is the patch-free active replacement path |
| capability ceiling | `PR_CAPBSET_DROP` / `cred->cap_bset` | monotonic, irreversible |
| filesystem / net / IPC | **Landlock** precedent; removed from PoC (required a kernel source patch) | canonical sealed-domain model; `root.readonly` plus patch-free BPF-LSM active response replace the removed patched path |
| resources | **cgroup v2** | continuous; DoS containment |
| sensitive interfaces | masked/ro paths, dropped sysctls, device policy | block release_agent / core_pattern / sysrq / mknod escapes |
| active per-domain policy + kill | **BPF-LSM** on `file_open`, cgroup-id-keyed `guarded` map; `bpf_send_signal(SIGKILL)` + `-EPERM` | done: runtime-loaded, patch-free/config-only active response |

**Why not native LSM hooks in the module:** `security_add_hooks()` is not
exported and `DEFINE_LSM` lives in `__init` — a loadable module **cannot** register
LSM hooks post-boot (intentional). Therefore:

- **PoC (loadable module):** the domain applies no_new_privs + cap bounding +
  cgroup + masked/readonly paths at creation, tracks the domain by fd/id, and is
  patch-free: it runs on a vanilla `CONFIG_RUST=y` kernel plus `CONFIG_KPROBES`
  and `CONFIG_KALLSYMS_ALL`. A small sibling `krunc_helper.ko` is loaded before
  `krunc.ko` and resolves non-exported primitives through a
  kprobe→`kallsyms_lookup_name` bootstrap. A **BPF-LSM** program now provides
  per-domain runtime policy + kill-on-escape: a static libbpf loader attaches it
  between `krunc create` and `krunc start`, pins the link, and guards exactly the
  container cgroup id. This remains patch-free/config-only (`CONFIG_BPF_SYSCALL`,
  `CONFIG_BPF_LSM`, BTF, BPF trampolines, `CONFIG_WERROR` off).
- **Mainline:** `krunc_domain` becomes an **in-tree LSM, modelled on Landlock**,
  with the `cred_prepare`/`bprm_committing_creds` inheritance hooks and a cred
  blob — giving the *true* first-class, sealed, inherited domain. This is the
  honest dividing line: the unprivileged sealed-inheritance property **requires
  in-tree changes** and cannot be a pure module.

## 5. Kernel vs userspace boundary

```
containerd / runc / youki / our CLI        ── USERSPACE ──
  parse & validate OCI config.json (untrusted; NEVER in kernel)
  manage images/layers/snapshots, CNI networking, cgroup hierarchy creation
  run OCI hooks; lifecycle/state bookkeeping; logging
  └─ compile policy → a fixed, versioned, bounded binary "domain spec"
                         │  create domainfd + configure + seal  (ioctl today;
                         ▼   jail()-style syscall if it graduates)
  krunc_domain                              ── KERNEL ──
  trivial, strict, bounds-checked parse of the binary spec (no JSON)
  atomic setup-and-exec (P1) + sealed lifetime enforcement (P2)
```

Complex parsing of untrusted input stays in userspace (attack surface); the
kernel consumes only a validated, fixed-layout blob. The kernel boundary is now
patch-free: no in-tree source patch or extra exported symbols are required.

## 6. ABI

A versioned, `#[repr(C)]`, bounds-checked request: header (`abi_version`, op,
section offsets/lengths, out `domain_id`/`domainfd`) + a flat bounded payload
(namespaces, uid/gid maps, argv/env, mounts[], masked/ro paths[], cap sets,
rlimits[], cgroup limits, user). The current binary spec carries no seccomp
program and no Landlock rules; active kill-on-escape is supplied by the
runtime-loaded BPF-LSM path.
Kernel side: `FromBytes`/`AsBytes`, reject unknown `abi_version`, cap every
count/length, single `copy_from_user`, validate-before-use. The ABI lives in one
Rust crate shared (and mirrored) by CLI and module; round-trip property-tested
and the kernel validator fuzzed from a userspace harness.

## 7. From v1 to v2

v1 (committed) already does P1's core: kernel-context `krunc_spawn` (clone w/o
CLONE_VM) → hostname/chroot → two-phase create/start → `kernel_execve`, driven by
a runc-compatible CLI and verified under QEMU + go-runc. v2:

1. introduce `Domain` (typestate) + the fd/id handle + registry refactor;
2. extend P1 to the full ordered sequence (uid/gid maps, no_new_privs, new mount
   API + pivot_root, caps, cgroup placement, user, richer eBPF-LSM policy);
3. rewrite the userspace adapter in Rust (oci-spec → domain spec);
4. extend the implemented BPF-LSM per-domain kill-on-escape (optional,
   privileged) beyond the VM-verified `file_open` tripwire;
5. extensive verification (see `docs/ROADMAP.md` + `plan`): OCI conformance,
   per-confinement host-side assertions, **post-setup escape-attempt tests**, and
   real containerd e2e;
6. document the in-tree LSM design as the mainline-graduation target.

See `docs/SECURITY.md` for the threat model and honest limits, and
`docs/research-notes/` for the cited research this design rests on.
