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
#include <linux/resource.h>
#include <linux/oom.h>
#include <linux/sched/user.h>
#include <linux/fs.h>
#include <linux/dcache.h>
#include <linux/mount.h>
#include <linux/fcntl.h>

/* Prototypes (the kernel builds with -Wmissing-prototypes -Werror). */
int krunc_set_hostname(const char *name, size_t len);
int krunc_chroot(const char *path);
int krunc_kill(pid_t nr, int sig);
void __noreturn krunc_exit(long code);
int krunc_apply_creds(u64 bset, u64 eff, u64 perm, u64 inh, u64 amb,
		      u32 uid, u32 gid, int no_new_privs, int caps_present);
int krunc_apply_rlimit(unsigned int resource, u64 soft, u64 hard);
void krunc_set_oom_score_adj(int adj);
int krunc_mount(const char *dev, const char *dir, const char *fstype,
		unsigned long flags);
int krunc_mkdir(const char *path, umode_t mode);
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
 * Terminate the *current* task in kernel context. A krunc container init is a
 * krunc_spawn()'d task that is meant to kernel_execve() into userspace; if its
 * entry function instead *returns* (a setup error, or a teardown before start),
 * the task would "return to userspace" with no valid user context and fault at
 * IP 0. Calling do_exit() makes such a task exit cleanly. Never use this on the
 * success path: there kernel_execve() has set up the user registers and the
 * entry function must return so the task enters the new program.
 */
void __noreturn krunc_exit(long code)
{
	do_exit(code);
}
EXPORT_SYMBOL_GPL(krunc_exit);

/*
 * Apply the container's privilege confinement to the *current* task, atomically
 * in kernel context, just before exec:
 *   - set the capability bounding/effective/permitted/inheritable/ambient sets
 *     exactly to @bset/@eff/@perm/@inh/@amb (the bounding set is the irreversible
 *     ceiling: nothing outside @bset can ever be regained; the other sets are
 *     applied as requested so no capability is granted that was not asked for),
 *     and
 *   - optionally set no_new_privs (required for a tamper-proof seccomp policy
 *     and to stop SUID privilege regain).
 *
 * Because this runs in the container init task before kernel_execve(), the
 * confinement is in force for the very first userspace instruction — there is no
 * intermediate userspace process in which the capability state could leak.
 */
int krunc_apply_creds(u64 bset, u64 eff, u64 perm, u64 inh, u64 amb,
		      u32 uid, u32 gid, int no_new_privs, int caps_present)
{
	struct cred *new;
	const u64 valid = (1ULL << (CAP_LAST_CAP + 1)) - 1;
	kuid_t kuid;
	kgid_t kgid;

	if (no_new_privs)
		task_set_no_new_privs(current);

	/* Only touch the capability state when the caller explicitly manages it.
	 * Note this is independent of @bset's value: an all-empty set is a valid,
	 * fully-confined request ("drop every capability"), not "unspecified". */
	if (!caps_present)
		return 0;

	new = prepare_creds();
	if (!new)
		return -ENOMEM;
	/* Each set is applied exactly as requested (defaulting to empty), so a
	 * container is never handed effective/permitted capabilities it did not
	 * ask for just because they are within the bounding ceiling. */
	new->cap_bset        = (kernel_cap_t){ .val = bset & valid };
	new->cap_effective   = (kernel_cap_t){ .val = eff  & valid };
	new->cap_permitted   = (kernel_cap_t){ .val = perm & valid };
	new->cap_inheritable = (kernel_cap_t){ .val = inh  & valid };
	new->cap_ambient     = (kernel_cap_t){ .val = amb  & valid };

	/* Drop to the target user/group (real, effective, saved and fs ids), all
	 * in the same cred so changing uid does not clear the caps we just set
	 * (unlike the setuid(2) path). Done while still privileged, before exec. */
	kgid = make_kgid(new->user_ns, gid);
	if (gid_valid(kgid)) {
		new->gid = new->egid = new->sgid = new->fsgid = kgid;
	}
	kuid = make_kuid(new->user_ns, uid);
	if (uid_valid(kuid)) {
		struct user_struct *new_user;

		new->uid = new->euid = new->suid = new->fsuid = kuid;
		/* Mirror set_user(): switch new->user so commit_creds() performs
		 * the RLIMIT_NPROC ucount transfer, which it only does when
		 * new->user changes. Without this the per-user process count
		 * underflows when the task exits (WARN in dec_rlimit_ucounts). */
		new_user = alloc_uid(kuid);
		if (!new_user) {
			abort_creds(new);
			return -EAGAIN;
		}
		free_uid(new->user);
		new->user = new_user;
	}

	/* Repoint the cred's ucounts at the (possibly new) uid so commit_creds()
	 * transfers the rlimit counters onto the correct ucounts, exactly as the
	 * setresuid(2) path does. */
	if (set_cred_ucounts(new) < 0) {
		abort_creds(new);
		return -ENOMEM;
	}

	commit_creds(new); /* consumes @new */
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_apply_creds);

/*
 * Apply one resource limit (setrlimit) to the current task before exec. This is
 * what do_prlimit() does for the simple case (do_prlimit is static): update
 * signal->rlim[resource] under the group-leader's task_lock. The container init
 * is still fully privileged here, so it may set any soft/hard pair. u64 maps
 * directly to unsigned long on the LP64 target (U64_MAX == RLIM_INFINITY).
 */
int krunc_apply_rlimit(unsigned int resource, u64 soft, u64 hard)
{
	struct rlimit *rlim;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
	/* A finite soft limit may not exceed the hard limit. */
	if (soft != (u64)RLIM_INFINITY && hard != (u64)RLIM_INFINITY && soft > hard)
		return -EINVAL;

	rlim = current->signal->rlim + resource;
	task_lock(current->group_leader);
	rlim->rlim_cur = (unsigned long)soft;
	rlim->rlim_max = (unsigned long)hard;
	task_unlock(current->group_leader);
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_apply_rlimit);

/*
 * Set the current task's OOM-killer score adjustment before exec. The init is
 * privileged here, so it may set oom_score_adj_min too (lower the floor). The
 * valid range is [OOM_SCORE_ADJ_MIN, OOM_SCORE_ADJ_MAX].
 */
void krunc_set_oom_score_adj(int adj)
{
	if (adj < OOM_SCORE_ADJ_MIN)
		adj = OOM_SCORE_ADJ_MIN;
	else if (adj > OOM_SCORE_ADJ_MAX)
		adj = OOM_SCORE_ADJ_MAX;

	task_lock(current->group_leader);
	current->signal->oom_score_adj = (short)adj;
	current->signal->oom_score_adj_min = (short)adj;
	task_unlock(current->group_leader);
}
EXPORT_SYMBOL_GPL(krunc_set_oom_score_adj);

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

/* init_mkdir() (fs/init.c) is __init code (freed after boot) — unusable at
 * container-creation time. We reimplement a kernel-context mkdir here. */

/*
 * Create directory @path (one level; the parent must already exist) in the
 * *current* task's mount namespace, relative to its (chrooted) root. Used by the
 * container init to materialize a nested mountpoint inside a just-mounted parent
 * — e.g. /dev/pts or /dev/shm inside the fresh /dev tmpfs — the way runc does,
 * so a stock containerd/Docker mount set applies cleanly. -EEXIST is benign.
 */
int krunc_mkdir(const char *path, umode_t mode)
{
	struct dentry *dentry, *res;
	struct path parent;
	int err;

	dentry = start_creating_path(AT_FDCWD, path, &parent, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	res = vfs_mkdir(mnt_idmap(parent.mnt), d_inode(parent.dentry), dentry, mode);
	err = IS_ERR(res) ? PTR_ERR(res) : 0;
	end_creating_path(&parent, dentry);
	return err;
}
EXPORT_SYMBOL_GPL(krunc_mkdir);
