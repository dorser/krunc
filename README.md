# krunc — a container runtime in the kernel

`krunc` ("kernel runc") is a proof-of-concept container runtime implemented as a
**Rust Linux kernel module**. Where `runc` is a userspace program that issues
`clone`/`unshare`/`mount`/`pivot_root`/`execve` syscalls to build a container,
krunc performs the entire container **orchestration inside the kernel**:
namespace creation, rootfs entry, hostname, and process exec all happen in
kernel context. Userspace only submits a one-line spec.

```
            userspace                    |            kernel
                                         |
  $ echo 'run rootfs=/c host=demo \      |   /dev/krunc (misc device, Rust)
          exec=/bin/sh arg=/init.sh' \   |        │ write_iter(): parse spec
        > /dev/krunc                     |        ▼
                                         |   user_mode_thread(CLONE_NEWPID|NEWNS|
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
   module parses the spec and calls **`user_mode_thread()`** with the namespace
   clone flags. This is the very primitive the kernel uses to create the real
   `init` at boot: it makes a task that starts in fresh namespaces and is allowed
   to later `kernel_execve()` into userspace. With `CLONE_NEWPID` the new task is
   **PID 1 of a brand-new PID namespace**.
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
two-phase lifecycle, plus a small userspace binary, `krunc` (in `cli/`), that
speaks the same command surface as `runc`:

```sh
krunc create <id> --bundle <dir> [--pid-file <f>]   # set up + block before exec
krunc start  <id>                                   # release -> exec entrypoint
krunc state  <id>                                   # OCI state JSON (created/running/stopped)
krunc kill   <id> <signal>
krunc delete <id>
krunc list ; krunc --version
```

It reads the OCI bundle's `config.json`, translates the supported subset
(`process.args`/`env`, `root.path`, `hostname`, `linux.namespaces`) into a krunc
kernel spec, and drives the module's `create`(paused)/`start`/`state`/`kill`/
`delete` ioctls. State is persisted under `--root` (default `/run/krunc`) like
runc. A captured standalone lifecycle run is in
[`docs/sample-oci-run.txt`](docs/sample-oci-run.txt).

This is the API a higher-level runtime expects. **containerd** drives an OCI
runtime through `containerd-shim-runc-v2`, which invokes it via the
`github.com/containerd/go-runc` client (`BinaryName` selects the binary). This
is **verified**: `conformance/` uses go-runc — the exact library the shim uses —
to drive krunc through `Create → State → Start → State → Delete` successfully
(see [`docs/sample-containerd-run.txt`](docs/sample-containerd-run.txt)).
Standing up the full containerd daemon needs a bit more (and lacks cgroups/stats
and tty console for now); see the *containerd* notes in
[`docs/DESIGN.md`](docs/DESIGN.md).

## Repository layout

```
module/                Rust kernel module (the runtime itself)
  krunc.rs             misc device, text + ioctl control, registry, container_entry
  Kbuild, Makefile     out-of-tree module build
kernel-patch/
  krunc_exports.c      tiny vmlinux shim: krunc_spawn + the primitives krunc needs
cli/
  main.go              runc/OCI-compatible CLI (create/start/state/kill/delete)
conformance/
  main.go              drives krunc via go-runc (containerd's runtime client)
examples/
  rootfs-skel/init.sh  example container entrypoint (the "app")
  bundle/config.json   example OCI bundle config
scripts/
  vm-setup.sh          install kernel + Rust-for-Linux toolchain on a test VM
  pin-rust.sh          pin the exact rustc/bindgen the kernel requires
  build-kernel.sh      configure + build a kernel with CONFIG_RUST + the shim
  build-module.sh      build the out-of-tree krunc.ko
  build-cli.sh         build the static krunc OCI CLI
  make-initramfs.sh    assemble busybox + krunc.ko + krunc CLI + rootfs/bundle
  run-qemu.sh          boot the test kernel under QEMU/KVM
  qemu-init.sh         the in-VM demo driver (text + OCI lifecycle + unload)
  run-test.sh          rebuild module + cli + initramfs + run QEMU (fast loop)
docs/
  DESIGN.md            architecture and rationale
  sample-run.txt       captured text-interface demo output
  sample-oci-run.txt   captured OCI runtime-CLI lifecycle output
```

## Build & run

krunc needs a kernel built with `CONFIG_RUST=y` plus a small vmlinux shim, so
everything is built and tested on a disposable VM (the demo boots the kernel
under QEMU/KVM, so a module bug never touches the build host). The flow:

```sh
# on a fresh Ubuntu VM with nested virtualization (e.g. an Azure D-series v5):
scripts/vm-setup.sh                 # build deps + rustup + clang/lld + qemu + busybox
# fetch a kernel source tree (linux-6.18 was used here), then:
scripts/pin-rust.sh   ~/linux-6.18  # install the rustc/bindgen the kernel wants
REPO=~/krunc KSRC=~/linux-6.18 scripts/build-kernel.sh   # kernel + shim (~5 min, 16 cores)
scripts/run-test.sh                 # build krunc.ko, make initramfs, boot QEMU demo
```

`scripts/build-kernel.sh` bases the config on `defconfig` + `kvm_guest.config`,
enables Rust and the namespaces, and compiles `kernel-patch/krunc_exports.c`
into vmlinux. Once the kernel is built once, `scripts/run-test.sh` is the fast
iteration loop.

Verified on: Linux 6.18, rustc 1.78.0, bindgen 0.65.1, clang/LLVM 18, x86-64.

## Status, hardening & limitations

This is a **proof of concept** with a deliberately hardened (narrow) boundary;
it is not production software. Notable simplifications and known limitations:

- **Boundary.** Fixed text + ioctl command formats; argv/env are bounded.
  A subset of the OCI `config.json` is honored (args, env, root, hostname,
  namespaces); cgroups, mounts, capabilities, seccomp, devices, hooks and
  user-namespace mapping are not yet.
- **containerd.** krunc implements the runc/OCI CLI, and `go-runc` (the library
  the containerd runc shim uses) drives it through the full lifecycle (verified,
  see `conformance/`). Standing up the full containerd daemon additionally needs
  cgroup placement, task-exit wiring and tty console support — or, more cleanly,
  a native `containerd-shim-krunc-v2`. See `docs/DESIGN.md` §7.
- **Privilege.** `run`/`create`/`kill` require the caller to be privileged
  (namespace creation needs `CAP_SYS_ADMIN`); there is no per-caller
  authorization beyond the device's file permissions.
- **Lifecycle.** The container registry detects liveness lazily (signal-0
  probe) but does not reap; exited containers linger in the table until
  `delete`/unload.
- **vmlinux shim.** `kernel-patch/krunc_exports.c` exports `krunc_spawn`
  (clone without `CLONE_VM`), re-exports `user_mode_thread`/`kernel_execve`, and
  adds thin `krunc_{set_hostname,chroot,kill}` helpers. All policy/logic lives in
  Rust; the shim only exposes generic primitives.

See [`docs/DESIGN.md`](docs/DESIGN.md) for the reasoning behind each choice and a
list of natural next steps (cgroups, pivot_root + mount setup, capability
dropping, an `ioctl`/netlink control plane, container reaping).
