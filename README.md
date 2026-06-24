# krunc — a container runtime in the kernel

`krunc` ("kernel runc") is a proof-of-concept container runtime implemented as a
**Rust Linux kernel module**. Where `runc` is a userspace program that issues
`clone`/`unshare`/`mount`/`pivot_root`/`execve` syscalls to build a container,
krunc performs the entire container **orchestration inside the kernel**:
namespace creation, rootfs entry, hostname, and process exec all happen in
kernel context. Userspace only submits a one-line spec.

> **Direction (v2 — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)).** This
> PoC is the foundation for a larger idea: give the Linux kernel a **first-class
> workload / security-domain object** (`krunc_domain`), in the spirit of a
> FreeBSD jail — a durable object that *represents* a workload after creation and
> enforces **sealed, monotonic, inherited** invariants on it for its whole
> lifetime. The point is not to move OCI/containerd into the kernel (those stay
> in userspace); it is to add the missing kernel *noun* so containers gain a
> tamper-proof, kernel-owned security domain that closes both the setup-escape
> window **and** post-setup escapes. Design: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md);
> threat model + honest limits: [`docs/SECURITY.md`](docs/SECURITY.md); plan:
> [`docs/ROADMAP.md`](docs/ROADMAP.md); cited research: [`docs/research-notes/`](docs/research-notes/).

```
            userspace                    |            kernel
                                         |
  $ echo 'run rootfs=/c host=demo \      |   /dev/krunc (misc device, Rust)
          exec=/bin/sh arg=/init.sh' \   |        │ write_iter(): parse spec
        > /dev/krunc                     |        ▼
                                         |   krunc_spawn(CLONE_NEWPID|NEWNS|
                                         |        │            NEWUTS|NEWIPC|NEWNET)
                                         |        ▼  (new task = PID 1 of new ns)
                                         |   container_entry()  [kernel context]
                                         |        ├─ krunc_set_hostname()
                                         |        ├─ krunc_chroot(rootfs)
                                         |        └─ kernel_execve("/bin/sh", …)
                                         |        ▼
        [container] Hello! pid=1  ◄──────────  becomes the container's userspace
        hostname=demo                    |        PID 1, fully isolated
```

It really works — see [`docs/sample-run.txt`](docs/sample-run.txt) for a full
captured run. Highlights from the demo (a container launched entirely by the
kernel from a single `echo`):

```
[container] hostname (UTS namespace) : krunc-demo
[container] my pid   (PID namespace) : 1        <- should be 1
[container] processes I can see (PID namespace):
PID   COMMAND
    1 sh
    6 ps
[container] filesystem root (mount ns + chroot):
bin  dev  init.sh  proc  sys  tmp

[vm] --- namespace isolation (host view of pid 83) ---
[vm]   pid: ISOLATED  (host pid:[4026531836] vs container pid:[4026532167])
[vm]   mnt: ISOLATED  (host mnt:[4026531832] vs container mnt:[4026532164])
[vm]   uts: ISOLATED  (host uts:[4026531838] vs container uts:[4026532165])
[vm]   ipc: ISOLATED  (host ipc:[4026531839] vs container ipc:[4026532166])
[vm]   net: ISOLATED  (host net:[4026531833] vs container net:[4026532168])
```

## How it works

A container is created without a single userspace orchestration syscall:

1. A `write()` to `/dev/krunc` runs in the calling process's context. The Rust
   module parses the spec and calls **`krunc_spawn()`** (a `kernel_clone()` that,
   like the primitive the kernel uses to create the real `init` at boot, makes a
   task that starts in fresh namespaces and is allowed to later `kernel_execve()`
   into userspace) with the namespace clone flags. With `CLONE_NEWPID` the new
   task is **PID 1 of a brand-new PID namespace**.
2. That task runs `container_entry()` in kernel context, which:
   - sets the container hostname in its private UTS namespace,
   - performs an **in-kernel chroot** into the container rootfs,
   - **`kernel_execve()`s** the requested binary, becoming the container's
     userspace PID 1.

The control device also supports listing (with live `running`/`exited` status)
and stopping containers.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the full design, the kernel-primitive
rationale, the userspace/kernel boundary, and limitations.

## Interface (`/dev/krunc`)

Deliberately narrow and busybox-friendly — the only interface is a one-line text
command written to the device:

| command | effect |
|---|---|
| `run rootfs=<hostpath> host=<name> exec=<path> [arg=<a> ...]` | create + start a container |
| `kill <hostpid>` | send SIGKILL to a container's init |
| `cat /dev/krunc` | list containers (`ID  PID  STATE  HOSTNAME`) |

`exec` is the container-relative binary path (argv[0]); each `arg=` appends an
argv entry. A default environment (`PATH`, `HOME`, `TERM`, `container=krunc`) is
provided by the kernel.

```sh
# start
echo 'run rootfs=/containers/demo host=demo exec=/bin/sh arg=/init.sh' > /dev/krunc
# list
cat /dev/krunc
# stop (by host-visible pid shown in the table)
echo 'kill 1234' > /dev/krunc
```

## OCI runtime CLI (drive it like `runc`)

krunc also exposes an **ioctl** control plane implementing an OCI-runtime-style
two-phase lifecycle, plus a small **all-Rust** userspace binary, `krunc` (in
`userspace/krunc-cli/`), that speaks the same command surface as `runc`:

```sh
krunc create <id> --bundle <dir> [--pid-file <f>]   # set up + block before exec
krunc start  <id>                                   # release -> exec entrypoint
krunc state  <id>                                   # OCI state JSON (created/running/stopped)
krunc kill   <id> <signal>
krunc delete <id>
krunc list ; krunc --version
```

It reads the OCI bundle's `config.json` (`userspace/krunc-oci`), translates the
supported subset (`process.args`/`env`, `root.path`, `hostname`,
`linux.namespaces`, `process.capabilities.bounding`,
`process.noNewPrivileges`) into a validated binary spec (`userspace/krunc-abi`),
and drives the module's `create`(paused)/`start`/`state`/`kill`/`delete` ioctls.
The kernel then applies the confinement — namespaces, in-kernel chroot, **the
capability bounding set and `no_new_privs`** — atomically before exec.

A captured run is in
[`docs/sample-v2-confinement.txt`](docs/sample-v2-confinement.txt): the OCI
container's capabilities are dropped to exactly the bounding set
(`CapBnd=00000000200004e1`) with `NoNewPrivs=1`, **verified from the host** via
`/proc/<pid>/status` — contrasted against the unconfined text-interface container
(`CapBnd=000001ffffffffff`).

This is the API a higher-level runtime expects: **containerd** drives an OCI
runtime through `containerd-shim-runc-v2` (via the `go-runc` client, with
`BinaryName` selecting the binary). An earlier Go prototype was verified driving
krunc through the full lifecycle; the project is now all-Rust and the remaining
work (a self-contained module via runtime symbol resolution, `pivot_root`) is
tracked in [`docs/ROADMAP.md`](docs/ROADMAP.md).

## Repository layout

```
module/                Rust kernel module (the runtime itself)
  krunc.rs             misc device, text + ioctl control, binary-spec decode,
                       registry, container_entry (chroot + caps + no_new_privs + exec)
  krunc_helper.c       small C sibling module: resolves the non-exported kernel
                       primitives via kprobe→kallsyms_lookup_name and re-exports
                       krunc_spawn, krunc_apply_creds + helpers (NO vmlinux patch)
  Kbuild, Makefile     out-of-tree build of both modules
userspace/             all-Rust userspace (Cargo workspace)
  krunc-abi/           versioned, bounds-checked binary spec (no_std-friendly, no unsafe)
  krunc-oci/           OCI config.json -> DomainSpec translation (serde)
  krunc-cli/           the runc-compatible `krunc` CLI (run/create/start/state/kill/delete)
examples/
  rootfs-skel/init.sh  example container entrypoint (the "app")
  bundle/config.json   example OCI bundle (with caps bounding + noNewPrivileges)
scripts/
  vm-setup.sh          install kernel + Rust-for-Linux toolchain on a test VM
  pin-rust.sh          pin the exact rustc/bindgen the kernel requires
  build-kernel.sh      configure + build a vanilla kernel with CONFIG_RUST +
                       KPROBES/KALLSYMS (no source patch)
  build-module.sh      build the out-of-tree krunc_helper.ko + krunc.ko
  build-cli.sh         build the static (musl) all-Rust krunc CLI
  make-initramfs.sh    assemble busybox + krunc_helper.ko + krunc.ko + CLI + rootfs/bundle
  run-qemu.sh          boot the test kernel under QEMU/KVM
  qemu-init.sh         the in-VM demo driver (text + OCI lifecycle + confinement + unload)
  run-interactive.sh   boot to a shell to drive krunc by hand (incl. `krunc run`)
  qemu-shell-init.sh   interactive in-VM init (loads krunc.ko, prints a cheatsheet)
  setup-containerd-image.sh  stage containerd + nerdctl + a busybox image
  run-containerd.sh    boot a guest where real containerd/nerdctl drive krunc
  qemu-containerd-init.sh    in-VM init that starts containerd with krunc as runtime
  run-test.sh          rebuild module + cli + initramfs + run QEMU (fast loop)
docs/
  ARCHITECTURE.md      the krunc_domain object design (v2 target)
  SECURITY.md          threat model, two pillars, honest limits
  ROADMAP.md           milestones + test matrix
  DESIGN.md            v1 design and rationale
  research-notes/      cited research the design rests on
  sample-v2-confinement.txt   all-Rust pipeline + host-verified capability drop
```

## Build & run

> **New here? See [`QUICKSTART.md`](QUICKSTART.md)** for a step-by-step,
> copy-pasteable walkthrough (provision a VM → build the kernel → run a container).

krunc needs a kernel built with `CONFIG_RUST=y` (plus `CONFIG_KPROBES` and
`CONFIG_KALLSYMS_ALL`, which let the helper module resolve the kernel primitives
it needs at load time — **no kernel source patch**), so everything is built and
tested on a disposable VM (the demo boots the kernel under QEMU/KVM, so a module
bug never touches the build host). The flow:

```sh
# on a fresh Ubuntu VM with nested virtualization (e.g. an Azure D-series v5):
scripts/vm-setup.sh                 # build deps + rustup + clang/lld + qemu + busybox
# fetch a kernel source tree (linux-6.18 was used here), then:
scripts/pin-rust.sh   ~/linux-6.18  # install the rustc/bindgen the kernel wants
REPO=~/krunc KSRC=~/linux-6.18 scripts/build-kernel.sh   # vanilla kernel (~5 min, 16 cores)
scripts/run-test.sh                 # build the modules, make initramfs, boot QEMU demo
```

`scripts/build-kernel.sh` bases the config on `defconfig` + `kvm_guest.config`
and enables Rust, the namespaces, and `KPROBES`/`KALLSYMS_ALL`. No source file is
added to the kernel tree: `module/krunc_helper.ko` resolves the non-exported
primitives at load time. Once the kernel is built once, `scripts/run-test.sh` is
the fast iteration loop.

### Run containers by hand

krunc is a **strict** OCI runtime: it faithfully applies the subset of
`config.json` it supports and, per the runtime-spec (`create`: *"if the runtime
cannot apply a property as specified, it MUST generate an error"*), it **rejects**
any config carrying a property it cannot honor — it never silently ignores or
weakens one. So drive it with a bundle inside that subset:

```sh
scripts/run-interactive.sh          # boots QEMU to a shell; inside:
#   krunc run busybox -- echo hello                 # one-shot (create+start+wait+delete)
#   krunc run busybox -- cat /proc/self/status      # caps dropped
#   krunc create demo --bundle /bundle              # the runc/OCI lifecycle directly
#   krunc start demo ; krunc state demo ; krunc delete demo
```

A runc-compatible CLI means containerd *can* drive krunc as its runtime
(`scripts/run-containerd.sh`, krunc as the `io.containerd.runc.v2` runc binary).
However, containerd's/nerdctl's **default** generated configs include properties
krunc does not model — a device cgroup (`linux.resources.devices`), `sysctls`,
a `seccomp` profile, and (for `-it`) `process.terminal` — so krunc
**rejects** them rather than running a container that does not match its spec.
Driving krunc from containerd therefore requires reducing the runtime config to
krunc's supported subset (or implementing those properties spec-faithfully).

Verified on: Linux 6.18, rustc 1.78.0, bindgen 0.65.1, clang/LLVM 18, x86-64.

## Status, hardening & limitations

This is a **proof of concept** with a deliberately hardened (narrow) boundary;
it is not production software. Notable simplifications and known limitations:

- **Config boundary (strict, per runtime-spec).** krunc applies a defined subset
  of `config.json` (args, env, cwd, root, hostname, namespaces, capabilities,
  cgroups pids/memory/cpu, mounts, masked/read-only paths, rlimits, oom score,
  user) and **rejects** — rather than silently ignoring — any other configured
  property (e.g. `process.terminal`, `process.user.umask`, `linux.seccomp`,
  `root.readonly`, `linux.sysctl`, `linux.devices`, `linux.resources.devices`,
  `linux.resources.memory.swap`, `hooks`, user-namespace mappings,
  id-mapped mounts, and non-flag mount options such as `size=`/`mode=` or
  propagation flags). Unmodeled fields are rejected at parse time
  (`deny_unknown_fields`), not dropped. This follows the runtime-spec `create`
  rule that a runtime MUST error on a property it cannot apply, and avoids quietly
  running a container that does not match its requested configuration.
- **containerd / nerdctl.** krunc is runc-CLI-compatible, so containerd's
  `io.containerd.runc.v2` shim can drive it (krunc as the runc binary). But the
  default configs containerd/nerdctl generate use properties outside krunc's
  subset (above), so krunc rejects them — `ctr run`/`nerdctl run` with default
  configs are refused by design. A reduced runtime config (or implementing those
  properties spec-faithfully) is required to run under containerd. The
  `--console-socket` terminal handoff and CNI networking are runc/containerd
  conventions outside the runtime-spec and are not implemented.
- **Privilege.** `run`/`create`/`kill` require the caller to be privileged
  (namespace creation needs `CAP_SYS_ADMIN`); there is no per-caller
  authorization beyond the device's file permissions.
- **Lifecycle.** The container registry detects liveness lazily (signal-0
  probe) but does not reap; exited containers linger in the table until
  `delete`/unload.
- **helper module (no kernel patch).** `module/krunc_helper.c` builds as a tiny
  C sibling module that resolves the non-exported kernel primitives at load time
  via `kprobe→kallsyms_lookup_name`, then re-exports `krunc_spawn` (clone without
  `CLONE_VM`), `krunc_execve`, and thin `krunc_{set_hostname,chroot,kill,…}`
  helpers for the Rust module. It is `insmod`ed before `krunc.ko`. All policy/logic
  lives in Rust; the helper only exposes generic primitives. This is what lets
  krunc run on a **vanilla** `CONFIG_RUST` kernel (with `CONFIG_KPROBES` +
  `CONFIG_KALLSYMS_ALL`) — no kernel source patch.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the reasoning behind each choice and a
list of natural next steps (cgroups, pivot_root + mount setup, capability
dropping, an `ioctl`/netlink control plane, container reaping).
