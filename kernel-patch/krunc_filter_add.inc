/*
 * krunc seccomp support — appended to net/core/filter.c by
 * scripts/patch-kernel.sh (idempotent; guarded by the KRUNC_FILTER_PATCH marker).
 *
 * Kernel-buffer variant of bpf_prog_create() that also applies a post-classic
 * transform/check callback (krunc uses seccomp_check_filter). This lets krunc
 * build and install a seccomp filter from kernel context — the container init
 * runs in the kernel just before execve — without copying the program from a
 * userspace address (there is no userspace yet). It is exactly bpf_prog_create()
 * plus the @trans argument that bpf_prog_create_from_user() already threads
 * through to bpf_prepare_filter().
 */
int krunc_bpf_prog_create_kern_trans(struct bpf_prog **pfp,
				     struct sock_fprog_kern *fprog,
				     bpf_aux_classic_check_t trans);
int krunc_bpf_prog_create_kern_trans(struct bpf_prog **pfp,
				     struct sock_fprog_kern *fprog,
				     bpf_aux_classic_check_t trans)
{
	unsigned int fsize = bpf_classic_proglen(fprog);
	struct bpf_prog *fp;

	/* Make sure new filter is there and in the right amounts. */
	if (!bpf_check_basics_ok(fprog->filter, fprog->len))
		return -EINVAL;

	fp = bpf_prog_alloc(bpf_prog_size(fprog->len), 0);
	if (!fp)
		return -ENOMEM;

	memcpy(fp->insns, fprog->filter, fsize);

	fp->len = fprog->len;
	fp->orig_prog = NULL;

	/*
	 * seccomp's constant-action cache (SECCOMP_ARCH_NATIVE) walks the
	 * original *classic* program via fp->orig_prog, so save it now — before
	 * bpf_prepare_filter() rewrites fp->insns into eBPF. This mirrors
	 * bpf_prog_create_from_user(save_orig=true) / bpf_prog_store_orig_filter().
	 */
	{
		struct sock_fprog_kern *fkprog;

		fkprog = kmalloc(sizeof(*fkprog), GFP_KERNEL);
		if (!fkprog) {
			__bpf_prog_free(fp);
			return -ENOMEM;
		}
		fkprog->len = fprog->len;
		fkprog->filter = kmemdup(fp->insns, fsize,
					 GFP_KERNEL | __GFP_NOWARN);
		if (!fkprog->filter) {
			kfree(fkprog);
			__bpf_prog_free(fp);
			return -ENOMEM;
		}
		fp->orig_prog = fkprog;
	}

	/* bpf_prepare_filter() frees the program on error. */
	fp = bpf_prepare_filter(fp, trans);
	if (IS_ERR(fp))
		return PTR_ERR(fp);

	*pfp = fp;
	return 0;
}
EXPORT_SYMBOL_GPL(krunc_bpf_prog_create_kern_trans);
