// SPDX-License-Identifier: GPL-2.0
/*
 * krunc_helper.c - kernel-side primitives for the krunc Rust module, built as a
 * standalone, out-of-tree module (NOT a vmlinux patch).
 *
 * krunc spawns an isolated userspace process from kernel context, which needs a
 * handful of kernel primitives that mainline does not EXPORT_SYMBOL (e.g.
 * kernel_clone, kernel_execve, set_fs_root, path_mount, do_exit). An out-of-tree
 * module normally cannot link those. Instead of patching vmlinux to export them
 * (which defeats the goal of running on an unmodified kernel), this module
 * resolves them at load time via kallsyms_lookup_name() — obtained through the
 * standard kprobe trick, since kallsyms_lookup_name itself is no longer exported
 * (5.7+). It then EXPORT_SYMBOL_GPL's small krunc_* wrappers that the Rust
 * `krunc` module links against.
 *
 * Requirements on the (otherwise unmodified) kernel: CONFIG_RUST=y (for krunc.ko
 * itself), CONFIG_KPROBES=y and CONFIG_KALLSYMS_ALL=y (the latter because one
 * resolved symbol, uts_sem, is a data object). No kernel source patch.
 *
 * CAVEAT (kernel upgrades): kallsyms resolves symbols by NAME only — it confirms
 * a symbol exists but CANNOT detect a changed prototype. The p_* pointer
 * signatures below are validated against kernel 6.18; calling a same-named symbol
 * whose signature drifted on a newer kernel would pass wrong/garbage arguments
 * (corruption). When moving to a new kernel, re-audit every p_* signature against
 * that tree (e.g. vfs_mkdir's argument count has changed across versions).
 *
 * All policy/logic lives in the Rust module; these are generic primitives only.
 * The struct-heavy work stays in C (with kernel headers) so the Rust side never
 * needs task_struct / cred / fs_struct / kernel_clone_args layout.
 */

#include <linux/module.h>
#include <linux/kprobes.h>
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
#include <linux/rwsem.h>
#include <linux/spinlock.h>
#include <linux/atomic.h>

/* ---- function pointers resolved from kallsyms at module init ---- */
static pid_t (*p_kernel_clone)(struct kernel_clone_args *args);
static int (*p_kernel_execve)(const char *filename,
			      const char *const *argv,
			      const char *const *envp);
static void (*p_set_fs_root)(struct fs_struct *fs, const struct path *path);
static void (*p_set_fs_pwd)(struct fs_struct *fs, const struct path *path);
static int (*p_kern_path)(const char *name, unsigned int flags, struct path *path);
static int (*p_path_mount)(const char *dev_name, const struct path *path,
			   const char *type_page, unsigned long flags,
			   void *data_page);
static struct dentry *(*p_start_creating_path)(int dfd, const char *pathname,
					       struct path *path,
					       unsigned int lookup_flags);
static void (*p_end_creating_path)(struct path *path, struct dentry *dentry);
static struct dentry *(*p_vfs_mkdir)(struct mnt_idmap *idmap, struct inode *dir,
				     struct dentry *dentry, umode_t mode);
static int (*p_vfs_mknod)(struct mnt_idmap *idmap, struct inode *dir,
			  struct dentry *dentry, umode_t mode, dev_t dev);
static int (*p_vfs_symlink)(struct mnt_idmap *idmap, struct inode *dir,
			    struct dentry *dentry, const char *oldname);
static void (*p_path_put)(const struct path *path);
static void (*p_do_exit)(long code);
static struct pid *(*p_find_get_pid)(pid_t nr);
static int (*p_kill_pid)(struct pid *pid, int sig, int priv);
static void (*p_put_pid)(struct pid *pid);
static struct cred *(*p_prepare_creds)(void);
static int (*p_commit_creds)(struct cred *new);
static void (*p_abort_creds)(struct cred *new);
static kuid_t (*p_make_kuid)(struct user_namespace *from, uid_t uid);
static kgid_t (*p_make_kgid)(struct user_namespace *from, gid_t gid);
static struct user_struct *(*p_alloc_uid)(kuid_t uid);
static void (*p_free_uid)(struct user_struct *up);
static int (*p_set_cred_ucounts)(struct cred *new);
static struct rw_semaphore *p_uts_sem;

/* Prototypes (built with -Wmissing-prototypes -Werror). */
int krunc_set_hostname(const char *name, size_t len);
int krunc_chroot(const char *path);
int krunc_kill(pid_t nr, int sig);
int krunc_task_exit_status(pid_t nr, int *status);
int krunc_watch_pid(pid_t nr);
void krunc_unwatch_pid(pid_t nr);
int krunc_get_exit_code(pid_t nr, int *code);
void __noreturn krunc_exit(long code);
int krunc_apply_creds(u64 bset, u64 eff, u64 perm, u64 inh, u64 amb,
		      u32 uid, u32 gid, int no_new_privs, int caps_present);
int krunc_apply_rlimit(unsigned int resource, u64 soft, u64 hard);
void krunc_set_oom_score_adj(int adj);
int krunc_mount(const char *dev, const char *dir, const char *fstype,
		unsigned long flags);
int krunc_mkdir(const char *path, umode_t mode);
int krunc_mknod(const char *path, umode_t mode, unsigned int maj, unsigned int min);
int krunc_symlink(const char *path, const char *target);
int krunc_write_file(const char *path, const char *data, size_t len);
pid_t krunc_spawn(int (*fn)(void *), void *arg, unsigned long flags);
int krunc_execve(const char *filename, const char *const *argv,
		 const char *const *envp);

/*
 * Create a task that runs @fn in kernel context and may later krunc_execve()
 * into userspace, in the namespaces selected by @flags (CLONE_NEW*). The low
 * byte of @flags is the exit signal (e.g. SIGCHLD). Deliberately does NOT set
 * CLONE_VM (the container init must not share the caller's address space).
 */
pid_t krunc_spawn(int (*fn)(void *), void *arg, unsigned long flags)
{
	struct kernel_clone_args args = {
		.flags		= (flags & ~(unsigned long)CSIGNAL),
		.exit_signal	= (flags & CSIGNAL),
		.fn		= fn,
		.fn_arg		= arg,
	};

	return p_kernel_clone(&args);
}
EXPORT_SYMBOL_GPL(krunc_spawn);

/* Exec a binary from kernel context (kernel_execve is not exported). */
int krunc_execve(const char *filename, const char *const *argv,
		 const char *const *envp)
{
	return p_kernel_execve(filename, argv, envp);
}
EXPORT_SYMBOL_GPL(krunc_execve);

/* Set the nodename (hostname) of the current task's UTS namespace. */
int krunc_set_hostname(const char *name, size_t len)
{
	struct new_utsname *u;

	if (len >= __NEW_UTS_LEN)
		return -EINVAL;

	down_write(p_uts_sem);
	u = utsname();
	memcpy(u->nodename, name, len);
	u->nodename[len] = '\0';
	up_write(p_uts_sem);
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_set_hostname);

/* In-kernel chroot: make @path the root and cwd of the current task. */
int krunc_chroot(const char *path)
{
	struct path root;
	int err;

	err = p_kern_path(path, LOOKUP_FOLLOW | LOOKUP_DIRECTORY, &root);
	if (err)
		return err;

	p_set_fs_root(current->fs, &root);
	p_set_fs_pwd(current->fs, &root);
	p_path_put(&root);
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_chroot);

/* Send signal @sig to the task with host-visible pid @nr. */
int krunc_kill(pid_t nr, int sig)
{
	struct pid *pid;
	int ret;

	pid = p_find_get_pid(nr);
	if (!pid)
		return -ESRCH;
	ret = p_kill_pid(pid, sig, 1);
	p_put_pid(pid);
	return ret;
}
EXPORT_SYMBOL_GPL(krunc_kill);

/*
 * Report the liveness/exit status of the task with host-visible pid @nr.
 *
 * Returns:
 *   1  - the task is still alive (running/sleeping/stopped, not a zombie);
 *        @status is left untouched.
 *   0  - the task has exited: it is a zombie (EXIT_ZOMBIE) or already dead but
 *        not yet released. @status (if non-NULL) is set to its wait(2)-style
 *        status word (task->exit_code), so the caller can record the exit code
 *        or termination signal even though the task has not been reaped yet.
 *  -1  - no task with that pid exists (already reaped / never existed).
 *
 * This lets krunc report a container whose init has exited but has not yet been
 * reaped by its parent (a lingering zombie) as STOPPED rather than RUNNING — a
 * plain kill(pid, 0) liveness probe cannot distinguish a zombie from a live
 * task — and to capture its exit status for `krunc state`.
 */
int krunc_task_exit_status(pid_t nr, int *status)
{
	struct pid *pid;
	struct task_struct *task;
	int ret;

	pid = p_find_get_pid(nr);
	if (!pid)
		return -1;
	/* get_pid_task() is EXPORT_SYMBOL_GPL; it returns a referenced task or
	 * NULL under RCU, so the task pointer is safe to dereference here. */
	task = get_pid_task(pid, PIDTYPE_PID);
	p_put_pid(pid);
	if (!task)
		return -1;

	if (READ_ONCE(task->exit_state)) {
		if (status)
			*status = task->exit_code;
		ret = 0;
	} else {
		ret = 1;
	}
	put_task_struct(task);
	return ret;
}
EXPORT_SYMBOL_GPL(krunc_task_exit_status);

/*
 * Eager exit-status capture.
 *
 * A container's init exits in its own user context (after execve), long after
 * krunc's code has gone, and its parent (the short-lived `krunc create` process)
 * has usually exited too — so by the time `krunc state` runs the init may already
 * have been reaped, and its exit code can no longer be read from the (now gone)
 * task. To capture it reliably, krunc registers each container init's pid here
 * and a kprobe on do_exit() records the exiting task's status word the instant it
 * terminates. krunc.ko reads it back lazily in `state`.
 *
 * The table is tiny and guarded by a spinlock so it is safe to touch from the
 * kprobe handler (atomic context) — unlike krunc.ko's sleeping-mutex registry.
 */
#define KRUNC_MAX_WATCH 64
static DEFINE_SPINLOCK(krunc_watch_lock);
static atomic_t krunc_num_watched = ATOMIC_INIT(0);
static struct krunc_watch_entry {
	pid_t pid;
	int   code;
	bool  in_use;
	bool  exited;
} krunc_watch[KRUNC_MAX_WATCH];

/* Begin tracking host-visible pid @nr so its exit status is captured. */
int krunc_watch_pid(pid_t nr)
{
	unsigned long flags;
	int i, slot = -1;

	spin_lock_irqsave(&krunc_watch_lock, flags);
	for (i = 0; i < KRUNC_MAX_WATCH; i++) {
		if (!krunc_watch[i].in_use) {
			slot = i;
			break;
		}
	}
	if (slot >= 0) {
		krunc_watch[slot].pid	 = nr;
		krunc_watch[slot].code	 = 0;
		krunc_watch[slot].in_use = true;
		krunc_watch[slot].exited = false;
		atomic_inc(&krunc_num_watched);
	}
	spin_unlock_irqrestore(&krunc_watch_lock, flags);
	return slot >= 0 ? 0 : -ENOSPC;
}
EXPORT_SYMBOL_GPL(krunc_watch_pid);

/* Stop tracking @nr and free its slot (called on container delete). */
void krunc_unwatch_pid(pid_t nr)
{
	unsigned long flags;
	int i;

	spin_lock_irqsave(&krunc_watch_lock, flags);
	for (i = 0; i < KRUNC_MAX_WATCH; i++) {
		if (krunc_watch[i].in_use && krunc_watch[i].pid == nr) {
			krunc_watch[i].in_use = false;
			atomic_dec(&krunc_num_watched);
		}
	}
	spin_unlock_irqrestore(&krunc_watch_lock, flags);
}
EXPORT_SYMBOL_GPL(krunc_unwatch_pid);

/* If @nr is tracked and has exited, store its wait-style status word in @code
 * and return 1; otherwise return 0. */
int krunc_get_exit_code(pid_t nr, int *code)
{
	unsigned long flags;
	int i, ret = 0;

	spin_lock_irqsave(&krunc_watch_lock, flags);
	for (i = 0; i < KRUNC_MAX_WATCH; i++) {
		if (krunc_watch[i].in_use && krunc_watch[i].pid == nr &&
		    krunc_watch[i].exited) {
			if (code)
				*code = krunc_watch[i].code;
			ret = 1;
			break;
		}
	}
	spin_unlock_irqrestore(&krunc_watch_lock, flags);
	return ret;
}
EXPORT_SYMBOL_GPL(krunc_get_exit_code);

/* kprobe pre-handler on do_exit(long code): record the status word for any
 * tracked task at the moment it terminates. Runs system-wide on every exit, so
 * it bails out immediately (no lock) when nothing is being watched. */
static int krunc_do_exit_pre(struct kprobe *p, struct pt_regs *regs)
{
	pid_t nr;
	long code;
	unsigned long flags;
	int i;

	if (atomic_read(&krunc_num_watched) == 0)
		return 0;

	nr   = task_pid_nr(current);
	code = (long)regs->di;	/* x86_64: do_exit's first arg is in RDI */

	spin_lock_irqsave(&krunc_watch_lock, flags);
	for (i = 0; i < KRUNC_MAX_WATCH; i++) {
		if (krunc_watch[i].in_use && krunc_watch[i].pid == nr &&
		    !krunc_watch[i].exited) {
			krunc_watch[i].code   = (int)code;
			krunc_watch[i].exited = true;
			break;
		}
	}
	spin_unlock_irqrestore(&krunc_watch_lock, flags);
	return 0;
}

static struct kprobe krunc_exit_kp = {
	.symbol_name = "do_exit",
	.pre_handler = krunc_do_exit_pre,
};

/* Terminate the current task in kernel context (no return-to-userspace fault). */
void __noreturn krunc_exit(long code)
{
	p_do_exit(code);
	/* p_do_exit never returns; satisfy __noreturn. */
	BUG();
}
EXPORT_SYMBOL_GPL(krunc_exit);

/*
 * Apply the container's privilege confinement to the current task, atomically in
 * kernel context just before exec: set the five capability sets exactly, set the
 * target uid/gid in one cred (so the caps are not cleared as setuid(2) would),
 * and optionally no_new_privs.
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

	if (!caps_present)
		return 0;

	new = p_prepare_creds();
	if (!new)
		return -ENOMEM;
	new->cap_bset        = (kernel_cap_t){ .val = bset & valid };
	new->cap_effective   = (kernel_cap_t){ .val = eff  & valid };
	new->cap_permitted   = (kernel_cap_t){ .val = perm & valid };
	new->cap_inheritable = (kernel_cap_t){ .val = inh  & valid };
	new->cap_ambient     = (kernel_cap_t){ .val = amb  & valid };

	kgid = p_make_kgid(new->user_ns, gid);
	if (gid_valid(kgid))
		new->gid = new->egid = new->sgid = new->fsgid = kgid;

	kuid = p_make_kuid(new->user_ns, uid);
	if (uid_valid(kuid)) {
		struct user_struct *new_user;

		new->uid = new->euid = new->suid = new->fsuid = kuid;
		/* Mirror set_user(): switch new->user so commit_creds() performs
		 * the RLIMIT_NPROC ucount transfer (only done when user changes). */
		new_user = p_alloc_uid(kuid);
		if (!new_user) {
			p_abort_creds(new);
			return -EAGAIN;
		}
		p_free_uid(new->user);
		new->user = new_user;
	}

	if (p_set_cred_ucounts(new) < 0) {
		p_abort_creds(new);
		return -ENOMEM;
	}

	p_commit_creds(new); /* consumes @new */
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_apply_creds);

/* Apply one resource limit (setrlimit) to the current task before exec. */
int krunc_apply_rlimit(unsigned int resource, u64 soft, u64 hard)
{
	struct rlimit *rlim;

	if (resource >= RLIM_NLIMITS)
		return -EINVAL;
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

/* Set the current task's OOM-killer score adjustment before exec. */
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

/* Mount @fstype from @dev onto @dir in the current task's mount namespace. */
int krunc_mount(const char *dev, const char *dir, const char *fstype,
		unsigned long flags)
{
	struct path target;
	int err;

	err = p_kern_path(dir, LOOKUP_FOLLOW, &target);
	if (err)
		return err;
	err = p_path_mount(dev, &target, fstype, flags, NULL);
	p_path_put(&target);
	return err;
}
EXPORT_SYMBOL_GPL(krunc_mount);

/* Create directory @path (one level) in the current task's mount namespace. */
int krunc_mkdir(const char *path, umode_t mode)
{
	struct dentry *dentry, *res;
	struct path parent;
	int err;

	dentry = p_start_creating_path(AT_FDCWD, path, &parent, LOOKUP_DIRECTORY);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	/* mnt_idmap() is a static inline (include/linux/mount.h), so it has no
	 * kallsyms entry — call it directly rather than resolving a pointer. */
	res = p_vfs_mkdir(mnt_idmap(parent.mnt), d_inode(parent.dentry), dentry, mode);
	err = IS_ERR(res) ? PTR_ERR(res) : 0;
	/* vfs_mkdir (dentry-returning form) takes ownership of @dentry: on error or
	 * when it splices a different dentry it has already dput() the one we passed
	 * in and returns the alternate (or ERR_PTR). We must hand end_creating_path
	 * the *returned* dentry @res, never the original — exactly as the kernel's
	 * own do_mkdirat() does. Passing @dentry here would dput() an already-freed
	 * dentry on the error/splice paths (refcount underflow → use-after-free). */
	p_end_creating_path(&parent, res);
	return err;
}
EXPORT_SYMBOL_GPL(krunc_mkdir);

/* Write @data (@len bytes) to the file at @path (e.g. a /proc/sys sysctl) from
 * kernel context, before exec. filp_open/kernel_write/filp_close are exported by
 * mainline, so this needs no kallsyms resolution. Used to apply OCI sysctls in
 * the container's namespaces while still privileged. */
int krunc_write_file(const char *path, const char *data, size_t len)
{
	struct file *f;
	loff_t pos = 0;
	ssize_t n;

	f = filp_open(path, O_WRONLY, 0);
	if (IS_ERR(f))
		return PTR_ERR(f);
	n = kernel_write(f, data, len, &pos);
	filp_close(f, NULL);
	if (n < 0)
		return (int)n;
	return (size_t)n == len ? 0 : -EIO;
}
EXPORT_SYMBOL_GPL(krunc_write_file);

/* Create a device node (@mode carries S_IFCHR/S_IFBLK | perms) at @path with
 * device number MKDEV(@maj, @min), in the current task's mount namespace. Used
 * to materialise the OCI default /dev nodes (null/zero/full/random/urandom/tty)
 * from kernel context before exec, while still privileged (vfs_mknod requires
 * CAP_MKNOD for char/block nodes). Mirrors do_mknodat(): vfs_mknod is the
 * int-returning form, so it does NOT take ownership of @dentry — we hand the
 * ORIGINAL dentry to end_creating_path (exactly as the kernel does). */
int krunc_mknod(const char *path, umode_t mode, unsigned int maj, unsigned int min)
{
	struct dentry *dentry;
	struct path parent;
	int err;

	dentry = p_start_creating_path(AT_FDCWD, path, &parent, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	err = p_vfs_mknod(mnt_idmap(parent.mnt), d_inode(parent.dentry), dentry,
			  mode, MKDEV(maj, min));
	p_end_creating_path(&parent, dentry);
	return err;
}
EXPORT_SYMBOL_GPL(krunc_mknod);

/* Create a symbolic link at @path pointing to @target, in the current task's
 * mount namespace. Used for the OCI default /dev symlinks (fd, stdin, stdout,
 * stderr → /proc/self/fd/...). Like vfs_mknod, vfs_symlink is int-returning and
 * does not consume @dentry, so the ORIGINAL dentry goes to end_creating_path. */
int krunc_symlink(const char *path, const char *target)
{
	struct dentry *dentry;
	struct path parent;
	int err;

	dentry = p_start_creating_path(AT_FDCWD, path, &parent, 0);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	err = p_vfs_symlink(mnt_idmap(parent.mnt), d_inode(parent.dentry),
			    dentry, target);
	p_end_creating_path(&parent, dentry);
	return err;
}
EXPORT_SYMBOL_GPL(krunc_symlink);

/* ---- kallsyms bootstrap + symbol resolution ---- */

static unsigned long (*p_kallsyms_lookup_name)(const char *name);

/* Obtain kallsyms_lookup_name's address via a kprobe (it is no longer exported). */
static int krunc_resolve_kln(void)
{
	struct kprobe kp = { .symbol_name = "kallsyms_lookup_name" };
	int ret;

	ret = register_kprobe(&kp);
	if (ret < 0)
		return ret;
	p_kallsyms_lookup_name = (void *)kp.addr;
	unregister_kprobe(&kp);
	return p_kallsyms_lookup_name ? 0 : -ENOENT;
}

#define KRUNC_RESOLVE(dst, name)					\
	do {								\
		unsigned long _a = p_kallsyms_lookup_name(name);	\
		if (!_a) {						\
			pr_err("krunc_helper: cannot resolve %s\n", name); \
			return -ENOENT;					\
		}							\
		(dst) = (void *)_a;					\
	} while (0)

static int __init krunc_helper_init(void)
{
	int ret = krunc_resolve_kln();

	if (ret) {
		pr_err("krunc_helper: kallsyms bootstrap failed: %d (needs CONFIG_KPROBES)\n", ret);
		return ret;
	}

	KRUNC_RESOLVE(p_kernel_clone, "kernel_clone");
	KRUNC_RESOLVE(p_kernel_execve, "kernel_execve");
	KRUNC_RESOLVE(p_set_fs_root, "set_fs_root");
	KRUNC_RESOLVE(p_set_fs_pwd, "set_fs_pwd");
	KRUNC_RESOLVE(p_kern_path, "kern_path");
	KRUNC_RESOLVE(p_path_mount, "path_mount");
	KRUNC_RESOLVE(p_start_creating_path, "start_creating_path");
	KRUNC_RESOLVE(p_end_creating_path, "end_creating_path");
	KRUNC_RESOLVE(p_vfs_mkdir, "vfs_mkdir");
	KRUNC_RESOLVE(p_vfs_mknod, "vfs_mknod");
	KRUNC_RESOLVE(p_vfs_symlink, "vfs_symlink");
	KRUNC_RESOLVE(p_path_put, "path_put");
	KRUNC_RESOLVE(p_do_exit, "do_exit");
	KRUNC_RESOLVE(p_find_get_pid, "find_get_pid");
	KRUNC_RESOLVE(p_kill_pid, "kill_pid");
	KRUNC_RESOLVE(p_put_pid, "put_pid");
	KRUNC_RESOLVE(p_prepare_creds, "prepare_creds");
	KRUNC_RESOLVE(p_commit_creds, "commit_creds");
	KRUNC_RESOLVE(p_abort_creds, "abort_creds");
	KRUNC_RESOLVE(p_make_kuid, "make_kuid");
	KRUNC_RESOLVE(p_make_kgid, "make_kgid");
	KRUNC_RESOLVE(p_alloc_uid, "alloc_uid");
	KRUNC_RESOLVE(p_free_uid, "free_uid");
	KRUNC_RESOLVE(p_set_cred_ucounts, "set_cred_ucounts");
	KRUNC_RESOLVE(p_uts_sem, "uts_sem");

	/* The do_exit kprobe captures container exit codes. Best-effort: if it
	 * cannot be registered, liveness/state still work, only the recorded exit
	 * code is unavailable. */
	ret = register_kprobe(&krunc_exit_kp);
	if (ret)
		pr_warn("krunc_helper: do_exit kprobe not registered (%d); exit codes unavailable\n",
			ret);

	pr_info("krunc_helper: kernel primitives resolved; krunc.ko may load\n");
	return 0;
}

static void __exit krunc_helper_exit(void)
{
	if (krunc_exit_kp.addr)
		unregister_kprobe(&krunc_exit_kp);
	pr_info("krunc_helper: unloaded\n");
}

module_init(krunc_helper_init);
module_exit(krunc_helper_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("krunc");
MODULE_DESCRIPTION("krunc kernel primitives (kallsyms-resolved; no vmlinux patch)");
