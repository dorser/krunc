/*
 * krunc seccomp support — appended to kernel/seccomp.c by
 * scripts/patch-kernel.sh (idempotent; guarded by the KRUNC_SECCOMP_PATCH
 * marker). Inserted inside the CONFIG_SECCOMP_FILTER block so it can use the
 * file-static seccomp helpers.
 *
 * Install a seccomp filter from a kernel-resident sock_filter[] onto the current
 * task. This mirrors seccomp_set_mode_filter()'s prepare -> attach -> assign
 * sequence, but the classic-BPF program comes from kernel memory: krunc's
 * container init builds it in kernel context just before execve, so unlike
 * runc/youki there is no userspace instruction window in which the policy could
 * be skipped or tampered with. Like any unprivileged filter install it requires
 * no_new_privs, which krunc sets immediately before calling this.
 */
extern int krunc_bpf_prog_create_kern_trans(struct bpf_prog **pfp,
					    struct sock_fprog_kern *fprog,
					    bpf_aux_classic_check_t trans);

int krunc_seccomp_install(struct sock_filter *insns, unsigned int len);
int krunc_seccomp_install(struct sock_filter *insns, unsigned int len)
{
	struct sock_fprog_kern fprog;
	struct seccomp_filter *sfilter;
	long ret;

	if (len == 0 || len > BPF_MAXINSNS)
		return -EINVAL;
	fprog.len = (unsigned short)len;
	fprog.filter = insns;

	/* Same gate as seccomp_prepare_filter(): nnp or CAP_SYS_ADMIN. */
	if (!task_no_new_privs(current) &&
	    !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))
		return -EACCES;

	sfilter = kzalloc(sizeof(*sfilter), GFP_KERNEL | __GFP_NOWARN);
	if (!sfilter)
		return -ENOMEM;

	mutex_init(&sfilter->notify_lock);
	ret = krunc_bpf_prog_create_kern_trans(&sfilter->prog, &fprog,
					       seccomp_check_filter);
	if (ret < 0) {
		kfree(sfilter);
		return ret;
	}
	refcount_set(&sfilter->refs, 1);
	refcount_set(&sfilter->users, 1);
	init_waitqueue_head(&sfilter->wqh);

	spin_lock_irq(&current->sighand->siglock);

	if (!seccomp_may_assign_mode(SECCOMP_MODE_FILTER)) {
		ret = -EINVAL;
		goto out;
	}

	ret = seccomp_attach_filter(0, sfilter);
	if (ret)
		goto out;
	/* Attached: the task owns it now; do not free below. */
	sfilter = NULL;
	seccomp_assign_mode(current, SECCOMP_MODE_FILTER, 0);
out:
	spin_unlock_irq(&current->sighand->siglock);
	if (sfilter)
		seccomp_filter_free(sfilter);
	return ret;
}
EXPORT_SYMBOL_GPL(krunc_seccomp_install);
