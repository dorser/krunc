# krunc design

This document explains how krunc creates containers from kernel space, why the
boundary is drawn where it is, and what the known limitations and next steps are.

## 1. Thesis

A container is just a process running with a private set of namespaces, a
private root filesystem, resource limits, and a reduced privilege/syscall
surface. A userspace runtime like `runc` assembles this with a sequence of
syscalls (`clone`/`unshare`, `mount`, `pivot_root`, `sethostname`,
`setns`, capability/seccomp setup, `execve`).

krunc asks: *what if the orchestration lived in the kernel instead?* A kernel
module receives a tiny spec and drives the same machinery directly through
in-kernel APIs, so the "runtime" is part of the kernel and the userspace
trigger is a single `write()`.

## 2. Control plane: a misc device

krunc registers a misc character device `/dev/krunc` using the Rust
`kernel::miscdevice` abstraction. The interface is intentionally minimal and
text-based so it is scriptable from the most minimal userland (busybox `echo` /
`cat`), with no bespoke client binary or shared ABI struct:

- `write_iter()` receives a single command line and either launches (`run …`) or
  stops (`kill <pid>`) a container.
- `read_iter()` renders the container table (`ID PID STATE HOSTNAME`).

State lives in a module-global registry (`kernel::sync::global_lock!` mutex
around a `KVec<Container>`); per-open file state is unused.

## 3. Spawning a container init in fresh namespaces

The key primitive is **`krunc_spawn(fn, arg, flags)`** — a thin wrapper (in
`krunc_helper.ko`) around the kernel's **`kernel_clone()`** with a kernel-function
entry (`.fn`/`.fn_arg`). This is conceptually the same mechanism the kernel uses
at boot to create the real `init`: it creates a task that runs `fn` in kernel
context but, unlike a `kthread`, is allowed to later `kernel_execve()` and
*become a userspace process*.

krunc calls it with the namespace clone flags:

```
CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD
```

Because `write()` runs in the caller's context, the new task is a child of the
calling process and — thanks to `CLONE_NEWPID` — **PID 1 of a new PID
namespace**. `SIGCHLD` makes it a reapable child. The other flags give it
private mount/UTS/IPC/network namespaces. Unlike `user_mode_thread()`/
`kernel_thread()`, `krunc_spawn` deliberately does **not** set `CLONE_VM`: krunc
may be called from an ordinary (possibly multi-threaded) userspace process, and
the container init must not share that caller's address space (the child gets its
own mm, which `execve` replaces).

The new task runs `container_entry()` (a `extern "C"` fn), which, still in
kernel context inside the new namespaces:

1. **hostname** — writes the container's UTS `nodename` (`krunc_set_hostname`).
2. **rootfs** — performs an in-kernel chroot: `kern_path()` + `set_fs_root()` +
   `set_fs_pwd()` (`krunc_chroot`). The task owns a private `fs_struct` (it was
   created without `CLONE_FS`), so this does not affect the host.
3. **exec** — `kernel_execve(argv[0], argv, envp)`. On success the kernel
   rewrites the task's saved registers to enter the new program; the function
   returns 0 and the program runs when `container_entry` returns. The task
   becomes the container's userspace PID 1.

## 4. The krunc_helper module (kallsyms shim — no kernel patch)

Out-of-tree modules may only link against `EXPORT_SYMBOL`'d symbols. The
primitives krunc needs (`kernel_clone`, `kernel_execve`, `set_fs_root`,
`path_mount`, `vfs_mkdir`, `do_exit`, the cred/rlimit helpers, …) are
deliberately *not* exported by mainline. Rather than patch vmlinux to export
them — which would defeat the goal of running on an **unmodified** kernel —
`module/krunc_helper.c` builds as a small C sibling module that:

- resolves each non-exported symbol **at load time** via
  `kprobe → kallsyms_lookup_name` (the kprobe trick is needed because
  `kallsyms_lookup_name` itself stopped being exported in 5.7); then
- `EXPORT_SYMBOL_GPL`s thin `krunc_*` wrappers — `krunc_spawn` (a `kernel_clone`
  without `CLONE_VM`), `krunc_execve`, and helpers that wrap the struct-/
  locking-heavy bits (`krunc_set_hostname`, `krunc_chroot`, `krunc_kill`,
  `krunc_apply_creds`, `krunc_mount`, `krunc_mkdir`, …) so the Rust side never
  needs `task_struct`/`fs_struct`/`cred`/`kernel_clone_args` layout.

`krunc_helper.ko` is `insmod`ed before `krunc.ko`; the two share the build's
`Module.symvers`, so `krunc.ko` links against the helper's exports with no extra
plumbing. The kernel needs only `CONFIG_RUST=y` (for `krunc.ko`), `CONFIG_KPROBES`
and `CONFIG_KALLSYMS_ALL` (the last because one resolved symbol, `uts_sem`, is a
data object) — **no source patch**. The struct-heavy work stays in C (with kernel
headers) precisely so the Rust module never depends on those layouts.

An alternative considered was building krunc fully in-tree as `obj-y` (which can
call any symbol with no exports). The kallsyms-helper + out-of-tree split was
chosen because it runs on a vanilla kernel and keeps a fast `insmod`/`rmmod`
iteration loop. Crucially, **all policy and logic remain in the Rust module** —
the helper only exposes generic primitives comparable to what the kernel already
provides internally.

## 5. Memory & lifetime details

- The spec is copied into a heap `KBox<ContainerCtx>` and handed to the new task
  via `ForeignOwnable::into_foreign()`. `container_entry` takes ownership with
  `from_foreign()`.
- argv strings are copied onto the kernel stack (bounded: ≤ 8 args × ≤ 256 B) so
  the heap context can be **freed before `execve`** — there is no per-container
  leak on the success path. On any failure path the `KBox` is dropped normally.
- If `krunc_spawn` fails, the leaked context is reclaimed and dropped.

## 6. stdio

The container inherits the file descriptors of the process that wrote to
`/dev/krunc`. Because a shell redirect (`echo … > /dev/krunc`) transiently makes
that process's fd 1 point at the device, the example container sets up its own
`/dev` (it has a private mount namespace) and binds stdio to `/dev/console`:

```sh
mount -t devtmpfs dev /dev && exec </dev/console >/dev/console 2>/dev/console
```

A more complete runtime would set up the container's stdio from the kernel side
(e.g. opening a provided console before exec), the way `runc` connects a
container to a pty.

## 7. OCI runtime CLI and containerd

To be drivable by a higher-level runtime, krunc adds an OCI-runtime-style
control plane on top of the same module.

**Kernel ioctl ABI.** Alongside the text `write()`/`read()` interface, the misc
device implements `ioctl`s carrying a small fixed `#[repr(C)]` struct
(`KruncCmd`, 32 bytes): `CREATE`, `START`, `STATE`, `KILL`, `DELETE`. `CREATE`
passes a pointer+length to a (newline `key=value`) spec, which the kernel copies
in and parses; the heavier, variable-length data (args, env, paths, namespace
set) stays text so the struct ABI is tiny and trivial to marshal from Go.

**Two-phase create/start.** OCI requires `create` to set a container up but
**not** run its entrypoint until `start`. krunc's `CREATE` spawns the container
init, which sets hostname + enters the rootfs and then **blocks** (a per-
container `AtomicU8` gate, polled with `msleep`) before `kernel_execve`. `START`
flips the gate so the init proceeds to exec; `DELETE` of a not-yet-started
container flips it to "doom" so the init exits instead. This mirrors runc's
`exec.fifo` pause point.

**The `krunc` CLI** (`cli/main.go`, static, pure stdlib) implements the runc
command surface — `create --bundle … <id>`, `start`, `state`, `kill`, `delete`,
`list`, `--version`. It reads the bundle's `config.json`, translates the
supported subset (`process.args`/`env`, `root.path`, `hostname`,
`linux.namespaces`) into the kernel spec, drives the ioctls, and persists per-id
state under `--root` (default `/run/krunc`) — the same model runc uses.

**Spawning from a userspace caller.** `user_mode_thread()`/`kernel_thread()`
force `CLONE_VM`, which would make the container share the *caller's* address
space — fine for a one-shot `busybox echo`, but it deadlocks a multi-threaded Go
process trying to exit while a paused container still shares its mm. So
`krunc_spawn()` clones **without** `CLONE_VM` (the child gets its own mm, which
`execve` replaces) while still copying the caller's file descriptors, so the
container inherits the caller's stdio.

**containerd.** containerd drives an OCI runtime through
`containerd-shim-runc-v2`, which calls the runtime via the
`github.com/containerd/go-runc` client and `exec`s the runtime binary
(configurable via the runtime options' `BinaryName`, the same hook crun/youki
use) with runc-style subcommands on a bundle the shim writes. krunc's CLI
implements that surface, and this is **verified**: `conformance/main.go` uses
`go-runc` itself to drive krunc through `Version → Create (paused) → State
(created) → Start → State (running) → State (stopped) → Delete` successfully
(`docs/sample-containerd-run.txt`). One subtlety surfaced and is worth noting:
the shim/`go-runc` pass explicit task stdio to `create` (non-terminal: the task
fifos); the container then inherits those, which is exactly what makes its
output reach containerd. (Without explicit IO, go-runc pipe-captures the
runtime's output and blocks because the container holds the pipe — so the IO
must be set, as the shim does.)

Bringing up the **full containerd daemon** on top of this needs a few more
pieces, and some remaining gaps:

- *Exit notification.* The shim sets `PR_SET_CHILD_SUBREAPER`, so a krunc
  container — a descendant of the shim that reparents when the short-lived
  `krunc create` process exits — reparents to the shim, which can then reap it
  and emit the task exit event. (This is promising but not yet end-to-end
  tested with the daemon.)
- *cgroups & stats.* The shim creates the cgroup and expects the runtime to
  place the container in it; krunc does not honor cgroups yet, so resource
  limits and `metrics`/`stats` are absent.
- *Console/stdio* for `terminal:true` (console-socket fd passing) is not
  implemented; `terminal:false` works via inherited fds.

The robust long-term path is **Path B**: a native `containerd-shim-krunc-v2`
that implements the Task ttRPC service and owns these semantics directly,
instead of impersonating runc. The OCI CLI here is the foundation for either
path.

## 8. Testing approach

krunc requires a kernel with `CONFIG_RUST=y` and the export shim, so it is built
and tested on a disposable VM. The demo boots the freshly built kernel **under
QEMU/KVM** with a busybox initramfs (`scripts/qemu-init.sh` is the in-VM
driver). This means:

- the build host is never modified and never at risk;
- a module bug panics a throwaway QEMU guest, not the VM;
- the inner loop is `build-module → make-initramfs → run-qemu` (seconds).

Isolation is verified two ways: the container prints its own view (hostname, PID
1, visible processes, rootfs, interfaces), and the host side compares
`/proc/<pid>/ns/*` inodes against its own. The OCI lifecycle is verified by
driving the `krunc` CLI through create → start → state → delete (DEMO 3).

A note on the kernel config: `CONFIG_RUST` is gated on
`!CALL_PADDING || RUSTC_VERSION >= 1.81`. With the pinned rustc 1.78 (the
kernel's documented minimum) the call-depth-tracking mitigation that selects
`CALL_PADDING` is disabled in `build-kernel.sh`; irrelevant for a PoC.

## 9. Limitations and next steps

This section describes the **original v1 PoC** baseline. Most of these
simplifications have since been implemented (cgroups v2, capability dropping, the
five cap sets, `process.user` uid/gid, config-driven mounts, masked/read-only
paths, the full OCI runtime-spec create path); see `docs/ROADMAP.md` for current
status. They are kept here for the design rationale.

Original v1 simplifications (see also the README):

- No cgroups (no CPU/memory/pids limits), no seccomp, no capability dropping, no
  user-namespace uid/gid mapping, no `pivot_root` + full mount setup (a chroot is
  used instead), no OCI runtime spec.
- The registry is lazily liveness-probed but never reaps; exited containers
  linger in the table.
- The control plane is text-only (no `ioctl`/netlink); errors surface via the
  `write()` return value and `dmesg`.

Natural next steps, roughly in order of value:

1. **cgroups** — create a cgroup and move the container init into it for
   CPU/memory/pids limits (in-kernel cgroup APIs). *(done)*
2. **Mounts** — `pivot_root` + mount a private `/proc`, `/sys`, `/dev` and
   honor a list of bind/overlay mounts from the spec, from kernel side.
   *(mounts done; `pivot_root` still pending — needed for an immutable rootfs.)*
3. **Privilege reduction** — drop capabilities and apply `no_new_privs` +
   `process.user` before `execve`. *(done.)* Further syscall/LSM-level hardening
   is deferred to a future **eBPF-LSM** program (attached at runtime, no kernel
   patch) rather than seccomp/Landlock, which required in-tree kernel patches and
   were removed.
4. **Lifecycle** — track exit (e.g. a `do_wait`/exit hook) to reap and update
   the registry; expose container exit codes.
5. **Control plane** — an `ioctl`/netlink API with a typed spec for richer
   configuration and structured status.
6. **stdio** — kernel-side console/pty setup so containers get clean stdio
   regardless of the caller.
