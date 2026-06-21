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

The key primitive is **`user_mode_thread(fn, arg, flags)`**. The kernel uses it
at boot to create the real `init` (`user_mode_thread(kernel_init, …)`): it
creates a task that runs `fn` in kernel context but, unlike a `kthread`, is
allowed to later `kernel_execve()` and *become a userspace process*.

krunc calls it with the namespace clone flags:

```
CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNET | SIGCHLD
```

Because `write()` runs in the caller's context, the new task is a child of the
calling process and — thanks to `CLONE_NEWPID` — **PID 1 of a new PID
namespace**. `SIGCHLD` makes it a reapable child. The other flags give it
private mount/UTS/IPC/network namespaces. (`user_mode_thread` additionally
forces `CLONE_VM`, the same transient mm-sharing the kernel's own init creation
uses; `execve` installs a fresh mm immediately after.)

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

## 4. The vmlinux export shim

Out-of-tree modules may only link against `EXPORT_SYMBOL`'d symbols. The
primitives krunc needs are deliberately *not* exported by mainline, so
`kernel-patch/krunc_exports.c` is compiled into vmlinux (`obj-y`) and:

- **re-exports** `user_mode_thread` and `kernel_execve` (existing, non-static
  functions);
- provides three **thin helpers** that wrap struct-/locking-heavy bits so the
  Rust side never needs `task_struct`/`fs_struct`/`uts`/`pid` layout:
  `krunc_set_hostname`, `krunc_chroot`, `krunc_kill`.

This keeps the runtime out-of-tree (fast `insmod`/`rmmod` iteration) while only
requiring the kernel to be built once. Crucially, **all policy and logic remain
in the Rust module** — the shim only exposes generic primitives comparable to
what the kernel already provides internally.

An alternative considered was building krunc in-tree as `obj-y` (which can call
any symbol with no exports). The export-shim + out-of-tree split was chosen for
a much faster module edit/build/load loop.

## 5. Memory & lifetime details

- The spec is copied into a heap `KBox<ContainerCtx>` and handed to the new task
  via `ForeignOwnable::into_foreign()`. `container_entry` takes ownership with
  `from_foreign()`.
- argv strings are copied onto the kernel stack (bounded: ≤ 8 args × ≤ 256 B) so
  the heap context can be **freed before `execve`** — there is no per-container
  leak on the success path. On any failure path the `KBox` is dropped normally.
- If `user_mode_thread` fails, the leaked context is reclaimed and dropped.

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

## 7. Testing approach

krunc requires a kernel with `CONFIG_RUST=y` and the export shim, so it is built
and tested on a disposable VM. The demo boots the freshly built kernel **under
QEMU/KVM** with a busybox initramfs (`scripts/qemu-init.sh` is the in-VM
driver). This means:

- the build host is never modified and never at risk;
- a module bug panics a throwaway QEMU guest, not the VM;
- the inner loop is `build-module → make-initramfs → run-qemu` (seconds).

Isolation is verified two ways: the container prints its own view (hostname, PID
1, visible processes, rootfs, interfaces), and the host side compares
`/proc/<pid>/ns/*` inodes against its own.

A note on the kernel config: `CONFIG_RUST` is gated on
`!CALL_PADDING || RUSTC_VERSION >= 1.81`. With the pinned rustc 1.78 (the
kernel's documented minimum) the call-depth-tracking mitigation that selects
`CALL_PADDING` is disabled in `build-kernel.sh`; irrelevant for a PoC.

## 8. Limitations and next steps

Current simplifications (see also the README):

- No cgroups (no CPU/memory/pids limits), no seccomp, no capability dropping, no
  user-namespace uid/gid mapping, no `pivot_root` + full mount setup (a chroot is
  used instead), no OCI runtime spec.
- The registry is lazily liveness-probed but never reaps; exited containers
  linger in the table.
- The control plane is text-only (no `ioctl`/netlink); errors surface via the
  `write()` return value and `dmesg`.

Natural next steps, roughly in order of value:

1. **cgroups** — create a cgroup and move the container init into it for
   CPU/memory/pids limits (in-kernel cgroup APIs).
2. **Mounts** — `pivot_root` + mount a private `/proc`, `/sys`, `/dev` and
   honor a list of bind/overlay mounts from the spec, from kernel side.
3. **Privilege reduction** — drop capabilities and install a seccomp filter
   before `execve`; optional user-namespace mapping.
4. **Lifecycle** — track exit (e.g. a `do_wait`/exit hook) to reap and update
   the registry; expose container exit codes.
5. **Control plane** — an `ioctl`/netlink API with a typed spec for richer
   configuration and structured status.
6. **stdio** — kernel-side console/pty setup so containers get clean stdio
   regardless of the caller.
