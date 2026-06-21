// SPDX-License-Identifier: GPL-2.0
/*
 * krunc_exports.c - kernel-side primitives exported for the krunc module.
 *
 * krunc is an out-of-tree Rust module that implements a container runtime in
 * the kernel. Out-of-tree modules may only link against EXPORT_SYMBOL'd
 * symbols, but a handful of the primitives krunc needs to spawn an isolated
 * userspace process from kernel context are intentionally *not* exported by
 * mainline. This file is compiled into vmlinux (obj-y) and:
 *
 *   1. Re-exports two existing, non-static primitives:
 *        - user_mode_thread(): create a task in fresh namespaces that can
 *          later kernel_execve() into a userspace program (this is exactly how
 *          the kernel creates PID 1 at boot).
 *        - kernel_execve(): exec a binary from kernel context.
 *
 *   2. Provides thin helpers that wrap struct-heavy / locking-heavy bits so the
 *      Rust side never has to know task_struct / fs_struct / uts / pid layout:
 *        - krunc_set_hostname(): set the *current* task's UTS namespace nodename.
 *        - krunc_chroot(): set the *current* task's fs root+pwd to a path
 *          (an in-kernel chroot, used to enter the container rootfs).
 *        - krunc_kill(): signal a container by its host-visible pid.
 *
 * All policy/logic lives in the Rust module; these are generic primitives only.
 */

#include <linux/module.h>
#include <linux/export.h>
#include <linux/sched.h>
#include <linux/sched/task.h>
#include <linux/sched/signal.h>
#include <linux/cred.h>
#include <linux/capability.h>
#include <linux/binfmts.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>
#include <linux/path.h>
#include <linux/pid.h>
#include <linux/utsname.h>
#include <linux/errno.h>
#include <linux/string.h>

/* Prototypes (the kernel builds with -Wmissing-prototypes -Werror). */
int krunc_set_hostname(const char *name, size_t len);
int krunc_chroot(const char *path);
int krunc_kill(pid_t nr, int sig);
int krunc_apply_creds(u64 cap_mask, int no_new_privs);
int krunc_mount(const char *dev, const char *dir, const char *fstype,
		unsigned long flags);
pid_t krunc_spawn(int (*fn)(void *), void *arg, unsigned long flags);

/* path_mount() is non-static (fs/internal.h) but not in a public header; declare
 * it here. The shim is built into vmlinux, so it may call non-exported symbols. */
int path_mount(const char *dev_name, const struct path *path,
	       const char *type_page, unsigned long flags, void *data_page);

/* Re-export existing primitives that mainline keeps internal. */
EXPORT_SYMBOL_GPL(user_mode_thread);
EXPORT_SYMBOL_GPL(kernel_execve);

/*
 * Create a task that runs @fn in kernel context and may later kernel_execve()
 * into userspace, in the namespaces selected by @flags (CLONE_NEW*). The low
 * byte of @flags is the exit signal (e.g. SIGCHLD).
 *
 * Unlike user_mode_thread()/kernel_thread(), this deliberately does NOT set
 * CLONE_VM: krunc may be called from an ordinary (possibly multi-threaded)
 * userspace process, and the container init must not share that caller's
 * address space (the child gets its own mm, which execve replaces). File
 * descriptors are still inherited (CLONE_FILES is not set, so they are copied),
 * which gives the container its stdio.
 */
pid_t krunc_spawn(int (*fn)(void *), void *arg, unsigned long flags)
{
	struct kernel_clone_args args = {
		.flags		= (flags & ~(unsigned long)CSIGNAL),
		.exit_signal	= (flags & CSIGNAL),
		.fn		= fn,
		.fn_arg		= arg,
	};

	return kernel_clone(&args);
}
EXPORT_SYMBOL_GPL(krunc_spawn);

/*
 * Set the nodename (hostname) of the UTS namespace of the *current* task.
 * Called from the container init thread, which already lives in its own
 * CLONE_NEWUTS namespace, so this only affects the container.
 */
int krunc_set_hostname(const char *name, size_t len)
{
	struct new_utsname *u;

	if (len >= __NEW_UTS_LEN)
		return -EINVAL;

	down_write(&uts_sem);
	u = utsname();
	memcpy(u->nodename, name, len);
	u->nodename[len] = '\0';
	up_write(&uts_sem);
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_set_hostname);

/*
 * In-kernel chroot: resolve @path and make it the root and cwd of the *current*
 * task's fs_struct. Because the caller is the container init thread (created
 * without CLONE_FS, so it owns a private fs_struct), this isolates the rootfs
 * to the container without touching the host.
 */
int krunc_chroot(const char *path)
{
	struct path root;
	int err;

	err = kern_path(path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &root);
	if (err)
		return err;

	set_fs_root(current->fs, &root);
	set_fs_pwd(current->fs, &root);
	path_put(&root);
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_chroot);

/*
 * Send signal @sig to the task with host-visible pid @nr. Used by krunc to
 * stop ("kill") a container by signalling its init.
 */
int krunc_kill(pid_t nr, int sig)
{
	struct pid *pid;
	int ret;

	pid = find_get_pid(nr);
	if (!pid)
		return -ESRCH;
	ret = kill_pid(pid, sig, 1);
	put_pid(pid);
	return ret;
}
EXPORT_SYMBOL_GPL(krunc_kill);

/*
 * Apply the container's privilege confinement to the *current* task, atomically
 * in kernel context, just before exec:
 *   - lower the capability bounding/effective/permitted/inheritable sets to
 *     @cap_mask and clear the ambient set (the bounding set is the irreversible
 *     ceiling: nothing outside @cap_mask can ever be regained), and
 *   - optionally set no_new_privs (required for a tamper-proof seccomp policy
 *     and to stop SUID privilege regain).
 *
 * Because this runs in the container init task before kernel_execve(), the
 * confinement is in force for the very first userspace instruction — there is no
 * intermediate userspace process in which the capability state could leak.
 */
int krunc_apply_creds(u64 cap_mask, int no_new_privs)
{
	struct cred *new;
	kernel_cap_t caps = { .val = cap_mask & ((1ULL << (CAP_LAST_CAP + 1)) - 1) };

	if (no_new_privs)
		task_set_no_new_privs(current);

	/* cap_mask == 0 means "unspecified": leave the capability sets untouched. */
	if (cap_mask == 0)
		return 0;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	new->cap_bset = caps;
	new->cap_effective = caps;
	new->cap_permitted = caps;
	new->cap_inheritable = caps;
	new->cap_ambient = (kernel_cap_t){ .val = 0 };
	commit_creds(new); /* consumes @new */
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_apply_creds);

/*
 * Mount @fstype (e.g. "proc", "sysfs") from source @dev onto @dir, in the
 * *current* task's mount namespace. Used by the container init (which has a
 * private CLONE_NEWNS mount namespace) to set up a fresh /proc and /sys before
 * dropping privileges. @dir is resolved relative to the (already chrooted) root.
 */
int krunc_mount(const char *dev, const char *dir, const char *fstype,
		unsigned long flags)
{
	struct path target;
	int err;

	/* LOOKUP_FOLLOW only (no LOOKUP_DIRECTORY): the mountpoint may be a file
	 * (e.g. masking /proc/sysrq-trigger by bind-mounting /dev/null over it)
	 * as well as a directory. */
	err = kern_path(dir, LOOKUP_FOLLOW, &target);
	if (err)
		return err;
	err = path_mount(dev, &target, fstype, flags, NULL);
	path_put(&target);
	return err;
}
EXPORT_SYMBOL_GPL(krunc_mount);
