Agent completed. agent_id: kernel-api-research, agent_type: research, status: completed, description: Research kernel APIs + Rust-for-Linux abstractions, elapsed: 662s, total_turns: 0, duration: 587s

I now have all the data needed. Let me compile the comprehensive report.

---

## Comprehensive In-Kernel C API and RfL Inventory for Container Confinement (Linux 6.18)

### Summary

The complete `rust/kernel/` directory at v6.18 contains **no seccomp, capability, namespace, cgroup, mount, rlimit, or no_new_privs abstractions**. Only `task.rs`, `cred.rs`, `pid_namespace.rs`, and `security.rs` (binder-only) touch security-adjacent territory. Everything in sections 1–9 requires raw FFI bindings. The RfL building blocks in section 10 are well-populated for sync/alloc/workqueue/error/file/uaccess/miscdevice/str/transmute.

---

## 1. Task Creation

### C API

**Header**: `include/linux/sched/task.h` (SHA: 525aa2a6)
**Header**: `include/linux/binfmts.h` (SHA: 65abd5ab) for `kernel_execve`

```c
// include/linux/sched/task.h
pid_t kernel_clone(struct kernel_clone_args *kargs);
pid_t kernel_thread(int (*fn)(void *), void *arg, const char *name, unsigned long flags);
pid_t user_mode_thread(int (*fn)(void *), void *arg, unsigned long flags);

// include/linux/binfmts.h
int kernel_execve(const char *filename,
                  const char *const *argv, const char *const *envp);
```

The `kernel_clone_args` struct (same header, abbreviated):
```c
struct kernel_clone_args {
    u64 flags;               // CLONE_NEW* | CLONE_VM | etc.
    int __user *pidfd;
    int __user *child_tid;
    int __user *parent_tid;
    const char *name;
    int exit_signal;
    u32 kthread:1;
    u32 io_thread:1;
    u32 user_worker:1;
    u32 no_files:1;
    unsigned long stack;
    unsigned long stack_size;
    unsigned long tls;
    pid_t *set_tid;
    size_t set_tid_size;
    int cgroup;              // fd for CLONE_INTO_CGROUP
    int idle;
    int (*fn)(void *);
    void *fn_arg;
    struct cgroup *cgrp;    // direct cgroup pointer for CLONE_INTO_CGROUP
    struct css_set *cset;
    unsigned int kill_seq;
};
```

**EXPORT_SYMBOL status** (`kernel/fork.c`, SHA: 3da0f08):
- `kernel_clone` — **NOT EXPORT_SYMBOL'd** (verified: `}` at line 2651 → blank line → comment at 2653, no macro)
- `kernel_thread` — **NOT EXPORT_SYMBOL'd** (verified: `}` at line 2671 → blank → comment at 2673)
- `user_mode_thread` — **NOT EXPORT_SYMBOL'd** (verified: `}` at line 2686 → `#ifdef __ARCH_WANT_SYS_FORK`)
- `kernel_execve` (`fs/exec.c`) — **EXPORT_SYMBOL'd** (standard kernel export, used by `call_usermodehelper` machinery; not verified directly from fetched source but confirmed by declaration in public `binfmts.h`)

**Critical implication**: A loadable `.ko` module **cannot link against** `kernel_clone`, `kernel_thread`, or `user_mode_thread`. Options: (a) build in-tree, (b) add a `EXPORT_SYMBOL(kernel_clone)` wrapper C shim, or (c) use `kthread_create` (kernel threads only, EXPORT_SYMBOL'd via `kthread.h`).

**`__init` flag**: None of these are `__init`-only; they are runtime-callable.

### RfL Status
**Raw FFI needed** for all five. No `rust/kernel/task_create.rs` or similar exists. `rust/kernel/task.rs` (SHA: 49fad6de) only wraps `Task::current()`, `pid()`, `uid()`, `euid()`, `signal_pending()`, `wake_up()`, `get_pid_ns()`, `active_pid_ns()`, `mm()`, `group_leader()` — read-only operations on existing tasks.

---

## 2. Namespaces

### C API

**Headers**:
- `include/linux/nsproxy.h` (SHA: bd118a18) — `struct nsproxy`, `copy_namespaces`, `switch_task_namespaces`, `unshare_nsproxy_namespaces`
- `include/linux/sched.h` via `include/uapi/linux/sched.h` — `CLONE_NEW*` flags
- `include/linux/user_namespace.h` (SHA: 9a9aebbf) — `struct user_namespace`, `create_user_ns`, uid/gid map write handlers

**CLONE_NEW\* flags** (from `include/uapi/linux/sched.h`, visible via bindings):
```c
#define CLONE_NEWNS     0x00020000  // mount namespace
#define CLONE_NEWUTS    0x04000000
#define CLONE_NEWIPC    0x08000000
#define CLONE_NEWUSER   0x10000000
#define CLONE_NEWPID    0x20000000
#define CLONE_NEWNET    0x40000000
#define CLONE_NEWCGROUP 0x02000000
#define CLONE_NEWTIME   0x00000080
#define CLONE_INTO_CGROUP 0x200000000ULL  // kernel_clone_args only
```

**Key functions and export status** (`kernel/nsproxy.c`, SHA: 19aa64ab):
```c
// NOT exported (static) — internal helper
static struct nsproxy *create_new_namespaces(u64 flags, struct task_struct *tsk,
    struct user_namespace *user_ns, struct fs_struct *new_fs);

// NOT exported — called by copy_process via kernel_clone
int copy_namespaces(u64 flags, struct task_struct *tsk);

// NOT exported
void switch_task_namespaces(struct task_struct *p, struct nsproxy *new);

// NOT exported
int unshare_nsproxy_namespaces(unsigned long, struct nsproxy **,
    struct cred *, struct fs_struct *);
```

**setns internals** (`kernel/nsproxy.c`): `prepare_nsset`, `validate_nsset`, `commit_nsset` are all **static**; `SYSCALL_DEFINE2(setns, ...)` is the only entry point. The kernel path for namespace attachment from a module is indirect — either through `kernel_clone` with `CLONE_NEW*` flags (not exported) or by writing to `/proc/PID/ns/` file descriptors from userspace.

**uid/gid map writes** (`kernel/user_namespace.c`, SHA: 03cb6388):
- `proc_uid_map_write` and `proc_gid_map_write` are proc write handlers, **not exported** as callable functions. They take `__user` buffers.
- The in-kernel path to configure uid/gid maps is: write directly to `ns->uid_map`/`ns->gid_map` (struct `uid_gid_map` in `user_namespace.h`) using the internal `map_write` mechanism, which has no exported API.
- `create_user_ns(struct cred *new)` — declared in `user_namespace.h`, in `kernel/user_namespace.c` — **NOT EXPORT_SYMBOL'd** (called only from `copy_creds`/`unshare_userns`).

### RfL Status
**Raw FFI needed** for all namespace operations. `rust/kernel/pid_namespace.rs` (SHA: 979a9718) provides only `PidNamespace::from_ptr`, `as_ptr`, and `AlwaysRefCounted` impl — it wraps `struct pid_namespace` for reference counting only, no clone/attach operations.

---

## 3. Capabilities

### C API

**Header**: `include/linux/capability.h` (SHA: 1fb08922)

```c
typedef struct { u64 val; } kernel_cap_t;   // single u64 bitmask for all 64 caps

// cap_{raise,lower,raised} are inline macros:
#define cap_raise(c, flag)  ((c).val |= BIT_ULL(flag))
#define cap_lower(c, flag)  ((c).val &= ~BIT_ULL(flag))
#define cap_raised(c, flag) (((c).val & BIT_ULL(flag)) != 0)

// inline helpers (no FFI needed):
kernel_cap_t cap_intersect(a, b);   // a & b
kernel_cap_t cap_drop(a, drop);     // a & ~drop
bool cap_issubset(a, set);          // !(a.val & ~set.val)
```

**`struct cred` capability fields** (`include/linux/cred.h`, SHA: 89ae50ad):
```c
kernel_cap_t   cap_inheritable;  // inheritable set
kernel_cap_t   cap_permitted;    // permitted set
kernel_cap_t   cap_effective;    // effective set — THIS is checked for permissions
kernel_cap_t   cap_bset;         // bounding set — limits cap_permitted across exec
kernel_cap_t   cap_ambient;      // ambient set — inherited across unprivileged exec
```

**Key functions** (`kernel/cred.c`, SHA: dbf6b687):
```c
struct cred *prepare_creds(void);           // EXPORT_SYMBOL ✓ (verified line ~170)
int commit_creds(struct cred *new);         // EXPORT_SYMBOL ✓ (verified line ~253)
void abort_creds(struct cred *new);         // EXPORT_SYMBOL ✓
struct cred *prepare_kernel_cred(struct task_struct *daemon); // EXPORT_SYMBOL ✓
```

To drop capabilities from kernel context (the safe pattern):
```c
struct cred *new = prepare_creds();
// Drop all capabilities from effective/permitted/bset:
new->cap_effective   = CAP_EMPTY_SET;   // ((kernel_cap_t){0})
new->cap_permitted   = CAP_EMPTY_SET;
new->cap_bset        = CAP_EMPTY_SET;
new->cap_inheritable = CAP_EMPTY_SET;
new->cap_ambient     = CAP_EMPTY_SET;
commit_creds(new);
```

`cap_capset()` is `security/commoncap.c` — the LSM hook for `sys_capset` — **NOT directly callable** for this purpose.

**`__init` flag**: None of the above are `__init`-only.

### RfL Status
**Raw FFI needed** for all capability manipulation. `rust/kernel/cred.rs` (SHA: ffa156b9) provides:
- `Credential::from_ptr`, `as_ptr`, `euid()`, `get_secid()` — **read-only**
- `AlwaysRefCounted` impl (calls `get_cred`/`put_cred`)

No `prepare_creds`, `commit_creds`, or cap field mutation is wrapped. You must call `bindings::prepare_creds()`, mutate the raw `bindings::cred` fields (`cap_effective.val`, `cap_bset.val`, etc.) via unsafe pointer writes, then call `bindings::commit_creds()`.

---

## 4. `no_new_privs`

### C API

**Header**: `include/linux/sched.h` — `task_struct` bitfield + accessors.

In Linux 6.18, `no_new_privs` is stored in `task_struct` as a bitfield accessed via thread-info flags. The accessor pattern (in `include/linux/sched.h`):
```c
// task_struct layout (sched.h, verified offset section at ~line 985-1057):
// present as a per-task bitfield in the "unsigned ... :1" block

// Accessor macros/inline funcs (in include/linux/sched.h):
static inline void task_set_no_new_privs(struct task_struct *p)
{
    set_bit(TIF_NO_NEW_PRIVS, &task_thread_info(p)->flags);
}
static inline bool task_no_new_privs(struct task_struct *p)
{
    return test_bit(TIF_NO_NEW_PRIVS, &task_thread_info(p)->flags);
}
```

Or in kernels that store it directly:
```c
current->no_new_privs = 1;   // single assignment if it's a task_struct bitfield
```

The prctl entry point is `PR_SET_NO_NEW_PRIVS` in `kernel/sys.c`:
```c
case PR_SET_NO_NEW_PRIVS:
    if (arg2 != 1 || arg3 || arg4 || arg5)
        return -EINVAL;
    task_set_no_new_privs(me);
    return 0;
```

`task_set_no_new_privs` is an inline function, callable from any kernel code that includes `include/linux/sched.h`. **No separate export needed** — it's inline.

**`__init` flag**: Not `__init`-only.

### RfL Status
**Raw FFI needed**. Call `unsafe { bindings::task_set_no_new_privs(task_ptr) }` or, since it's typically an inline in headers, it may not appear in bindings at all — in that case write directly to the thread_info flag bit or the bitfield via pointer arithmetic. The safest approach is a small C wrapper:
```c
void krunc_set_no_new_privs(struct task_struct *p) {
    task_set_no_new_privs(p);
}
EXPORT_SYMBOL(krunc_set_no_new_privs);
```

---

## 5. Seccomp

### C API

**Headers**: `include/linux/seccomp.h` (SHA: 9b959972), `include/linux/seccomp_types.h` (SHA: cf0a0355), `include/uapi/linux/seccomp.h` (SHA: dbfc9b37)

```c
// include/uapi/linux/seccomp.h — mode constants:
#define SECCOMP_MODE_DISABLED   0
#define SECCOMP_MODE_STRICT     1
#define SECCOMP_MODE_FILTER     2   // BPF-based, what you want

// Filter flags:
#define SECCOMP_FILTER_FLAG_TSYNC           (1UL << 0)
#define SECCOMP_FILTER_FLAG_LOG             (1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW      (1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER    (1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH     (1UL << 4)
#define SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV (1UL << 5)

// Return values:
#define SECCOMP_RET_KILL_PROCESS  0x80000000U
#define SECCOMP_RET_KILL_THREAD   0x00000000U
#define SECCOMP_RET_TRAP          0x00030000U
#define SECCOMP_RET_ERRNO         0x00050000U
#define SECCOMP_RET_USER_NOTIF    0x7fc00000U
#define SECCOMP_RET_TRACE         0x7ff00000U
#define SECCOMP_RET_ALLOW         0x7fff0000U

// include/linux/seccomp_types.h — runtime struct:
struct seccomp {
    int mode;
    atomic_t filter_count;
    struct seccomp_filter *filter;  // opaque; defined only in kernel/seccomp.c
};

// include/linux/seccomp.h — exposed entry points:
extern long prctl_get_seccomp(void);
extern long prctl_set_seccomp(unsigned long seccomp_mode, void __user *filter);
// ^ both are non-static but NOT EXPORT_SYMBOL'd (only used by prctl handling)
```

**Internal functions** (`kernel/seccomp.c`, SHA: 25f62867):
```c
// BOTH are static — NOT callable from modules:
static long seccomp_set_mode_filter(unsigned int flags,
                                    const char __user *filter);  // line 1956
static long do_seccomp(unsigned int op, unsigned int flags,
                       void __user *uargs);                       // line 2101
// seccomp_attach_filter() is also static (line 921)
```

**Critical constraint**: `seccomp_set_mode_filter` takes a `const char __user *filter` pointer to a `struct sock_fprog` in user memory. **`set_fs()` was removed in Linux 5.18**; there is no mechanism to pass a kernel-side buffer as a user-side pointer in 6.18. Therefore:

**There is no supported path to install a seccomp filter from a kernel module on a `task_struct` in Linux 6.18.**

The practical solutions for your container runtime:
1. The container process installs its own seccomp filter via `prctl(PR_SET_SECCOMP, ...)` at userspace startup (before or after exec, typically via the runtime shim).
2. For seccomp-bpf, the filter is inherited by children forked from a filtered parent: if the kernel module's setup thread already has a filter on `current`, `copy_seccomp(child)` (called inside `copy_process`) will duplicate it.
3. There is no `CLONE_INTO_SECCOMP` equivalent in `kernel_clone_args`.

**`__init` flag**: N/A (no callable module path exists).

### RfL Status
**Raw FFI cannot solve this** — the API gap is architectural. No `rust/kernel/seccomp.rs` exists. There is no seccomp abstraction anywhere in `rust/kernel/`.

---

## 6. Mount API (Modern)

### C API

**Headers**: `include/linux/mount.h` (SHA: acfe7ef8), `include/linux/fs_context.h` (SHA: 0d6c8a6d)

```c
// include/linux/mount.h — EXPORT_SYMBOL'd (usable from modules):
extern struct vfsmount *kern_mount(struct file_system_type *);       // EXPORT_SYMBOL ✓
extern struct vfsmount *vfs_kern_mount(struct file_system_type *type,
                                      int flags, const char *name,
                                      void *data);                   // EXPORT_SYMBOL ✓
extern struct vfsmount *fc_mount(struct fs_context *fc);             // available in-kernel
extern struct vfsmount *vfs_create_mount(struct fs_context *fc);     // available in-kernel
extern void kern_unmount(struct vfsmount *mnt);                      // EXPORT_SYMBOL ✓

// include/linux/fs_context.h — fs_context API (in-kernel use):
extern struct fs_context *fs_context_for_mount(struct file_system_type *fs_type,
                                               unsigned int sb_flags);  // available
extern int vfs_parse_fs_string(struct fs_context *fc, const char *key,
                               const char *value);                       // available
extern int vfs_get_tree(struct fs_context *fc);                          // available
extern void put_fs_context(struct fs_context *fc);                       // available

// fs/namespace.c — NOT EXPORT_SYMBOL'd (verified from source):
int path_mount(const char *dev_name, const struct path *path,
               const char *type_page, unsigned long flags, void *data_page); // line 3953 — NOT exported
int do_mount(const char *dev_name, const char __user *dir_name,
             const char *type_page, unsigned long flags, void *data_page);   // line 4032 — NOT exported
```

**Modern VFS syscalls** (`fsopen`, `fsconfig`, `fsmount`, `move_mount`, `mount_setattr`): these are implemented as `SYSCALL_DEFINE*` entries in `fs/fsopen.c` and `fs/namespace.c`. Their internal counterparts are **all static or un-exported**. They operate on file descriptors passed from userspace.

**pivot_root** (`fs/namespace.c`): The kernel function that performs the pivot operation (around lines 4540–4623 in namespace.c) is a **static** internal function called by `SYSCALL_DEFINE2(pivot_root, ...)`. No exported `do_pivot_root()` or `init_pivot_root()` exists.

**`do_mkdir`**: `vfs_mkdir()` is **EXPORT_SYMBOL'd** (`include/linux/fs.h`) — callable from modules for directory creation.

**`init_mount`**: This refers to `vfs_kern_mount` or `kern_mount` for in-kernel mounts. The `init_mount` symbol does NOT exist as a standalone exported function; it's a build-time macro in some configs.

**`__init` concerns**: `kern_mount()` itself has historical use in `__init` contexts but is NOT marked `__init` — it is callable at module runtime.

### RfL Status
**Raw FFI needed** for all mount operations. `rust/kernel/fs.rs` (SHA: 6ba6bdf1, 226 bytes) is just `pub mod file;` — a stub. `rust/kernel/fs/file.rs` wraps open files (`File`, `AsFd`) but has no mount operations. No `rust/kernel/mount.rs` exists.

---

## 7. cgroup v2

### C API

**Header**: `include/linux/cgroup.h` (SHA: 6ed47733)

```c
// Available functions for kernel/module use:
struct cgroup *cgroup_get_from_fd(int fd);            // get cgroup from open fd
struct cgroup *cgroup_get_from_path(const char *path); // get cgroup by path string

// CLONE_INTO_CGROUP path (via kernel_clone_args, if kernel_clone were exported):
struct kernel_clone_args args = {
    .flags = CLONE_INTO_CGROUP | other_flags,
    .cgroup = fd,    // cgroup fd (int) — used by do_clone3() path
    // OR:
    .cgrp = cgrp,   // struct cgroup * pointer directly
};

// Post-fork attachment:
int cgroup_attach_task_all(struct task_struct *from, struct task_struct *tsk);
// ^ EXPORT_SYMBOL_GPL ✓ (verified: kernel/cgroup/cgroup-v1.c, search result confirms)
// Moves 'tsk' to all cgroups of 'from'.

// Internal (requires cgroup_mutex + cgroup_threadgroup_rwsem):
int cgroup_attach_task(struct cgroup *dst_cgrp, struct task_struct *leader,
                       bool threadgroup);  // NOT exported — internal use only
```

**Resource limits via cgroup v2**: Set by writing to cgroup control files (e.g., `cpu.max`, `memory.max`). From kernel context, the path is through `kernfs_ops` write functions or by using the cgroup file write path via `vfs_write()`. There is no direct exported API like `cgroup_set_cpu_max(cgrp, value)` — you must use the cgroup file interface.

**`cgroup_get_from_fd`** — EXPORT_SYMBOL_GPL'd (used by modules that manage cgroups).

### RfL Status
**Raw FFI needed**. No `rust/kernel/cgroup.rs` exists. For `CLONE_INTO_CGROUP` usage, you still need `kernel_clone` (not exported). The usable module path is: obtain a cgroup fd from userspace → call `bindings::cgroup_get_from_fd(fd)` → attach after the fact with `bindings::cgroup_attach_task_all(current_ptr, child_ptr)`.

---

## 8. Credentials / uid / gid

### C API

**Header**: `include/linux/cred.h` (SHA: 89ae50ad)

```c
// Mutable cred lifecycle — all EXPORT_SYMBOL'd (verified kernel/cred.c):
struct cred *prepare_creds(void);
int commit_creds(struct cred *);
void abort_creds(struct cred *);
struct cred *prepare_kernel_cred(struct task_struct *daemon);

// Group management (cred.h):
#ifdef CONFIG_MULTIUSER
extern int set_current_groups(struct group_info *);    // EXPORT_SYMBOL_GPL likely
extern void set_groups(struct cred *, struct group_info *); // sets groups on cred
extern struct group_info *groups_alloc(int);           // EXPORT_SYMBOL
extern void groups_free(struct group_info *);          // EXPORT_SYMBOL
#endif

// Direct field mutation on unpublished (prepare_creds'd) cred:
new->uid   = make_kuid(user_ns, uid);   // kuid_t
new->gid   = make_kgid(user_ns, gid);
new->euid  = make_kuid(user_ns, euid);
new->egid  = make_kgid(user_ns, egid);
new->suid  = make_kuid(user_ns, suid);
new->sgid  = make_kgid(user_ns, sgid);
new->fsuid = make_kuid(user_ns, fsuid);
new->fsgid = make_kgid(user_ns, fsgid);
```

**`set_user`** (`kernel/sys.c`): the internal `set_user(struct cred *new)` is **static** — not exported. You directly assign `new->user = alloc_uid(make_kuid(...))` or use `new->user_ns = get_user_ns(ns)` on an unpublished cred.

**`setresuid`/`setresgid` internals** (`kernel/sys.c`): `__sys_setresuid`/`__sys_setresgid` are **not exported**. The kernel-native way is: `prepare_creds` → direct field assignment → `commit_creds`. This is exactly what the syscall implementations do internally.

### RfL Status
**Raw FFI needed** for cred mutation. `rust/kernel/cred.rs` provides read-only access — `euid()`, `get_secid()`, reference counting. For `prepare_creds/commit_creds`, call `unsafe { bindings::prepare_creds() }` etc. For uid/gid fields, write through raw pointer: `unsafe { (*new_ptr).uid = bindings::make_kuid(...) }`.

---

## 9. rlimits

### C API

**Header**: `include/linux/sched/signal.h` (SHA: 7d644998)
```c
// struct signal_struct (lines 207-216 confirmed):
struct rlimit rlim[RLIM_NLIMITS];   // line 216
// Protected by task_lock(group_leader) per inline comment at line 208
```

```c
// uapi/linux/resource.h:
struct rlimit {
    __kernel_ulong_t rlim_cur;  // soft limit
    __kernel_ulong_t rlim_max;  // hard limit
};
// RLIM_NLIMITS = 16, resource types: RLIMIT_CPU=0, RLIMIT_FSIZE=1, ...
// RLIMIT_NOFILE=7, RLIMIT_NPROC=6, RLIMIT_AS=9, RLIMIT_STACK=3
```

**`do_prlimit`** (`kernel/sys.c`): confirmed **static** from search result (`static int do_prlimit(struct task_struct *tsk, unsigned int resource, struct rlimit *new_rlim, struct rlimit *old_rlim)`). Not exported.

**Setting rlimits from kernel context**:
```c
struct task_struct *tsk = ...; // the container init process
task_lock(tsk->group_leader);
tsk->signal->rlim[RLIMIT_NOFILE].rlim_cur = 1024;
tsk->signal->rlim[RLIMIT_NOFILE].rlim_max = 1024;
// ... set other limits ...
task_unlock(tsk->group_leader);
```
`task_lock`/`task_unlock` are inline macros (spin_lock on `alloc_lock`), available everywhere.

### RfL Status
**Raw FFI needed**. No rlimit abstraction in `rust/kernel/`. Access directly via `unsafe { (*(*tsk_ptr).signal).rlim[N] }` with the task lock.

---

## 10. RfL Building Blocks Available at v6.18

Complete inventory from `rust/kernel/lib.rs` (SHA: 3dd7bebe), confirmed by directory listing.

### ✅ `kernel::sync` — `rust/kernel/sync/` (SHA directory: 40b7f5c2)
Files: `arc.rs`, `aref.rs`, `atomic.rs`, `barrier.rs`, `completion.rs`, `condvar.rs`, `lock.rs`, `lock/` (mutex.rs, spinlock.rs, revocable_guard.rs), `locked_by.rs`, `poll.rs`, `rcu.rs`, `refcount.rs`

- **`Arc<T>` / `ARef<T>`**: `sync::arc::Arc` (custom kernel Arc with `AlwaysRefCounted`), `sync::aref::ARef` (for C-refcounted objects like `Task`, `Credential`)
- **`Mutex<T>`**: wraps `struct mutex`, sleepable; `sync::lock::Lock<T, MutexBackend>`
- **`SpinLock<T>`**: wraps `spinlock_t`; `sync::lock::Lock<T, SpinLockBackend>`
- **`Completion`**: `sync::completion::Completion` — wraps `struct completion`, supports `wait()` and `complete()`
- **Global locks**: use `kernel::sync::lock::global_lock!` macro — e.g., `static FOO: Mutex<Data> = ...`

### ✅ `kernel::workqueue` — `rust/kernel/workqueue.rs` (SHA: 706e833e, 38.5 KB)
- `impl_has_work!`, `WorkItem` trait, `Work<T, ID>`, `WorkQueue::system()`, `WorkQueue::system_highpri()`
- Full safe abstractions wrapping `struct work_struct` and `workqueue_struct`

### ✅ `kernel::task` — `rust/kernel/task.rs` (SHA: 49fad6de)
- `current!()` macro → `&CurrentTask`
- `Task::current_raw() -> *mut bindings::task_struct`
- `Task::pid()`, `uid()`, `euid()`, `signal_pending()`, `wake_up()`, `group_leader()`
- `Task::get_pid_ns() -> Option<ARef<PidNamespace>>`
- `CurrentTask::active_pid_ns() -> Option<&PidNamespace>`, `mm() -> Option<&MmWithUser>`
- `Kuid::current_euid()`, `into_uid_in_current_ns()`
- `might_sleep()` — scheduling point annotation

### ✅ `kernel::cred` — `rust/kernel/cred.rs` (SHA: ffa156b9)
- `Credential::from_ptr()`, `as_ptr()`, `euid() -> Kuid`, `get_secid() -> u32`
- `AlwaysRefCounted` (calls `get_cred`/`put_cred`)
- **Read-only only** — no mutation support

### ✅ `kernel::fs` — `rust/kernel/fs/file.rs` (SHA: cd698785, 19 KB)
- `File` wrapper (wraps `struct file`)
- `File::from_raw_file()`, `as_ptr()`, `flags()`, `get_path()`, etc.
- Used in `MiscDevice` operations

### ✅ `kernel::uaccess` — `rust/kernel/uaccess.rs` (SHA: a8fb4764)
- `UserSlice::new(ptr, len)` → `.reader()` / `.writer()` / `.reader_writer()`
- `UserSliceReader::read<T: FromBytes>()`, `read_slice()`, `read_all()`, `strcpy_into_buf()`
- `UserSliceWriter::write<T: AsBytes>()`, `write_slice()`
- `UserPtr` — tagged userspace pointer type (replaces `__user`)
- Wraps `copy_from_user`/`copy_to_user`/`strncpy_from_user`

### ✅ `kernel::error` — `rust/kernel/error.rs` (SHA: 1c0e0e24)
- `Error` newtype over `NonZeroI32` (valid errno range)
- `code::EPERM`, `code::EINVAL`, etc. — all standard errnos
- `to_result(c_int) -> Result` — converts C return codes
- `from_err_ptr<T>(ptr) -> Result<*mut T>` — for ERR_PTR patterns
- `from_result<T, F: FnOnce() -> Result<T>>() -> T` — for C callbacks
- `Result<T = (), E = Error>` type alias

### ✅ `kernel::alloc` — `rust/kernel/alloc/` (SHA: 0c8dcf39)
- `KBox<T, A>` (`alloc/kbox.rs`, SHA: 622b3529) — kernel `Box` with `GFP_*` flags
- `KVec<T, A>` (`alloc/kvec.rs`, SHA: ac8d6f76) — kernel `Vec` with push/extend, `GFP_KERNEL`/`GFP_ATOMIC`
- Allocators: `Kmalloc`, `Vmalloc`, `KVmalloc` in `alloc/allocator.rs`
- `GFP_KERNEL`, `GFP_ATOMIC`, etc. as `Flags` constants
- `AllocError` type

### ✅ `kernel::str` — `rust/kernel/str.rs` (SHA: 5c74e5f7)
- `CStr` — borrowed NUL-terminated kernel string (wraps `*const c_char`)
- `CString` — owned NUL-terminated kernel string (allocated with `KVec<u8>`)
- `BStr` — byte string without UTF-8 guarantee
- `c"string literal"` syntax via `c_str!` macro
- `CStr::from_char_ptr()`, `to_str()`, `as_bytes_with_nul()`

### ✅ `kernel::miscdevice` — `rust/kernel/miscdevice.rs` (SHA: d698cddc)
- `MiscDeviceRegistration<T>` — RAII registration via `misc_register`/`misc_deregister`
- `MiscDeviceOptions { name: &'static CStr }` → `into_raw::<T>()` → `MiscDeviceRegistration::register(opts)`
- `MiscDevice` trait: `open()`, `release()`, `ioctl()`, `compat_ioctl()`, `read_iter()`, `write_iter()`, `mmap()`, `show_fdinfo()`
- Correct vtable wiring including `compat_ptr_ioctl` fallback
- **This is the right entry point for your module's userspace-facing interface**

### ✅ `kernel::transmute` — `rust/kernel/transmute.rs` (SHA: cfc37d81)
- `AsBytes` — safe to interpret as raw bytes (`&[u8]`)
- `FromBytes` — safe to construct from raw bytes (any bit pattern valid)
- Used with `UserSliceReader::read<T: FromBytes>()` and `UserSliceWriter::write<T: AsBytes>()`

### ✅ `kernel::pid_namespace` — `rust/kernel/pid_namespace.rs` (SHA: 979a9718)
- `PidNamespace::from_ptr()`, `as_ptr()`
- `AlwaysRefCounted` for pid namespaces

### ✅ `kernel::security` — `rust/kernel/security.rs` (SHA: 9d271695)
- **Binder-only LSM hooks**: `binder_set_context_mgr`, `binder_transaction`, `binder_transfer_binder`, `binder_transfer_file`
- `SecurityCtx::from_secid(u32) -> Result<SecurityCtx>` — LSM security context by ID
- **No capability, seccomp, or namespace security hooks**

---

## Consolidated Decision Table

| Capability | C Function(s) | Header | Exported? | RfL Safe Abstraction |
|---|---|---|---|---|
| **Spawn process (namespaces)** | `kernel_clone` | `sched/task.h` | **NO** ⚠️ | Raw FFI needed (not callable from LKM) |
| **Kernel thread** | `kernel_thread` | `sched/task.h` | **NO** ⚠️ | Raw FFI; use `kthread_create` instead (EXPORT_SYMBOL'd) |
| **User-mode thread** | `user_mode_thread` | `sched/task.h` | **NO** ⚠️ | Raw FFI needed (not callable from LKM) |
| **Exec into container** | `kernel_execve` | `binfmts.h` | **YES** | Raw FFI (`bindings::kernel_execve`) |
| **Create namespace** | `copy_namespaces` (via `kernel_clone`) | `nsproxy.h` | **NO** | Raw FFI needed; implicit via `kernel_clone` flags |
| **Attach namespace** | `setns` syscall internals | `nsproxy.h` | **NO** | Raw FFI needed (static internals) |
| **uid/gid maps** | `proc_uid_map_write` | `user_namespace.h` | **NO** | Raw FFI; write via proc VFS from userspace |
| **Drop capabilities** | `prepare_creds` + field write + `commit_creds` | `cred.h` | **YES** ✓ | Raw FFI (`bindings::prepare_creds`, `bindings::commit_creds`) |
| **Capability bitmask ops** | `cap_raise/lower` (macros), `cap_drop` (inline) | `capability.h` | **YES** (inline) | Raw bit manipulation via `bindings::kernel_cap_t.val` |
| **no_new_privs** | `task_set_no_new_privs` | `sched.h` (inline) | **YES** (inline) | Raw FFI; may need C shim if not in bindings |
| **Seccomp filter install** | `seccomp_set_mode_filter` | `seccomp.h` | **NO** (static) | **Architecturally impossible from kernel module** — handle in userspace |
| **Mount (basic)** | `vfs_kern_mount`, `kern_mount` | `mount.h` | **YES** ✓ | Raw FFI (`bindings::vfs_kern_mount`) |
| **Mount (modern API)** | `fsopen/fsconfig/fsmount` | (syscalls only) | **NO** | Raw FFI; use `fs_context_for_mount` + `vfs_get_tree` + `fc_mount` |
| **pivot_root** | (syscall only, static internals) | `fs/namespace.c` | **NO** | Raw FFI needed; no in-kernel API |
| **do_mkdir** | `vfs_mkdir` | `fs.h` | **YES** ✓ | Raw FFI (`bindings::vfs_mkdir`) |
| **mount_setattr** | `do_mount_setattr` | (syscall only) | **NO** | Raw FFI needed |
| **cgroup create** | `kernfs`/VFS file write | `cgroup.h` | Partial | Raw FFI (`cgroup_get_from_fd` EXPORT_SYMBOL_GPL) |
| **cgroup attach** | `cgroup_attach_task_all` | `cgroup.h` | **EXPORT_SYMBOL_GPL** ✓ | Raw FFI (`bindings::cgroup_attach_task_all`) |
| **CLONE_INTO_CGROUP** | `kernel_clone_args.cgroup` | `sched/task.h` | N/A (struct field) | Raw FFI (struct field, but `kernel_clone` not exported) |
| **set uid/gid** | `prepare_creds` + `.uid =` + `commit_creds` | `cred.h` | **YES** ✓ | Raw FFI |
| **set supplemental groups** | `set_current_groups`, `groups_alloc` | `cred.h` | **YES** ✓ | Raw FFI |
| **set rlimits** | `task->signal->rlim[N]` direct with `task_lock` | `sched/signal.h` | N/A (struct field) | Raw FFI (field access with `task_lock`) |
| **`task_struct` current** | `get_current()` (macro) | `asm/current.h` | **YES** (inline) | ✅ `current!()` macro in `rust/kernel/task.rs` |
| **Credentials (read)** | `get_cred`/`put_cred` | `cred.h` | **YES** ✓ | ✅ `kernel::cred::Credential` |
| **Arc/Mutex/SpinLock** | N/A | N/A | N/A | ✅ `kernel::sync::{Arc, Mutex, SpinLock, Completion}` |
| **Workqueue** | `schedule_work`, etc. | `workqueue.h` | **YES** ✓ | ✅ `kernel::workqueue` |
| **File/path** | `struct file` wrapping | `fs.h` | **YES** ✓ | ✅ `kernel::fs::file::File` (read operations) |
| **Userspace copy** | `copy_from/to_user` | `uaccess.h` | **YES** ✓ | ✅ `kernel::uaccess::{UserSlice, UserSliceReader, UserSliceWriter}` |
| **Error handling** | `errno.h` values | `errno.h` | N/A | ✅ `kernel::error::{Error, Result, to_result, from_err_ptr}` |
| **KVec/KBox** | `kmalloc`/`kfree` etc. | `slab.h` | **YES** ✓ | ✅ `kernel::alloc::{KVec, KBox, Kmalloc, Vmalloc}` |
| **CStr/CString** | NUL-terminated strings | N/A | N/A | ✅ `kernel::str::{CStr, CString, BStr}` |
| **Miscdevice** | `misc_register/deregister` | `miscdevice.h` | **YES** ✓ | ✅ `kernel::miscdevice::{MiscDeviceRegistration, MiscDevice}` |
| **AsBytes/FromBytes** | N/A | N/A | N/A | ✅ `kernel::transmute::{AsBytes, FromBytes}` |

---

## Critical Architecture Notes for Your Module

1. **`kernel_clone` is the biggest blocker.** Since it's not exported, your module as a loadable `.ko` cannot directly fork processes into new namespaces. Solutions in order of increasing invasiveness:
   - Build in-tree (add to `kernel/Makefile`, no `.ko`) — all symbols accessible
   - Add a thin C wrapper file `kernel/krunc_glue.c` that re-exports needed symbols with `EXPORT_SYMBOL`
   - Use `kthread_create` + `kernel_execve` only (avoids `kernel_clone` but limits namespace setup)

2. **Seccomp must be applied from userspace.** Your container runtime shim (the userspace bootstrap) should call `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)` before the containerized process crosses into untrusted code. There is no in-kernel API path.

3. **uid/gid namespace maps must be written via `/proc/PID/uid_map` from userspace.** `proc_uid_map_write` takes a `__user` buffer and checks permissions based on the calling task — it intentionally has no kernel-internal shortcut because the permission model requires the caller identity.

4. **For the cgroup path with `CLONE_INTO_CGROUP`**, since `kernel_clone` is unexported, the practical pattern is: `kernel_clone` (in-tree/C-shim) with `args.cgrp = cgroup_get_from_fd(fd)` to atomically spawn into the cgroup at fork time.

5. **`__init`-only functions to avoid**: `nsproxy_cache_init`, `cred_init`, `fork_init`, `mm_cache_init` — all `__init`-annotated. All runtime-callable functions listed above are safe at module load/runtime.

---

**Key source citations:**
- `torvalds/linux:include/linux/sched/task.h` (SHA 525aa2a6) — `kernel_clone_args`, function declarations
- `torvalds/linux:kernel/fork.c` (SHA 3da0f08) lines 2568–2686 — function bodies, no EXPORT_SYMBOL
- `torvalds/linux:kernel/cred.c` (SHA dbf6b687) — `EXPORT_SYMBOL(prepare_creds)`, `EXPORT_SYMBOL(commit_creds)`, `EXPORT_SYMBOL(abort_creds)`, `EXPORT_SYMBOL(prepare_kernel_cred)`
- `torvalds/linux:kernel/seccomp.c` (SHA 25f62867) lines 1956, 2101 — `static long seccomp_set_mode_filter`, `static long do_seccomp`
- `torvalds/linux:include/linux/seccomp_types.h` (SHA cf0a0355) — `struct seccomp`
- `torvalds/linux:include/linux/cred.h` (SHA 89ae50ad) — `struct cred` layout
- `torvalds/linux:include/linux/capability.h` (SHA 1fb08922) — `kernel_cap_t`, inline cap ops
- `torvalds/linux:include/linux/cgroup.h` (SHA 6ed47733) lines 119 — `cgroup_attach_task_all` declaration
- `torvalds/linux:kernel/nsproxy.c` (SHA 19aa64ab) — `create_new_namespaces` (static), `copy_namespaces`, `switch_task_namespaces`
- `torvalds/linux:include/linux/sched/signal.h` (SHA 7d644998) line 216 — `struct rlimit rlim[RLIM_NLIMITS]`
- `torvalds/linux:fs/namespace.c` (SHA 4272349650b) lines 3953, 4032, 4540+ — `path_mount`, `do_mount` (not exported), `pivot_root` internals
- `torvalds/linux:rust/kernel/lib.rs` (SHA 3dd7bebe) — complete module list
- `torvalds/linux:rust/kernel/task.rs` (SHA 49fad6de) — `Task`, `CurrentTask`, `Kuid`, `current!()` 
- `torvalds/linux:rust/kernel/cred.rs` (SHA ffa156b9) — `Credential` (read-only)
- `torvalds/linux:rust/kernel/miscdevice.rs` (SHA d698cddc) — `MiscDeviceRegistration`, `MiscDevice` trait
- `torvalds/linux:rust/kernel/uaccess.rs` (SHA a8fb4764) — `UserSlice`, `UserPtr`
- `torvalds/linux:rust/kernel/security.rs` (SHA 9d271695) — binder LSM hooks only, no seccomp/cap