/*
 * krunc Landlock support — appended to security/landlock/syscalls.c by
 * scripts/patch-kernel-seccomp.sh (idempotent, marker-delimited). It lives here
 * because it uses landlock's create/append/merge ruleset functions and the
 * file-static credential blob accessor, all visible in this translation unit.
 *
 * Enforce a sealed Landlock filesystem domain on the current task that handles
 * the write/create/remove access rights but grants them only beneath @rw_paths;
 * read and execute are left unhandled, so they stay unrestricted. The result is
 * an immutable rootfs with a few writable scratch directories, inherited across
 * execve and (under no_new_privs) un-relaxable from inside — the kernel's own
 * sealed-domain primitive, applied from kernel context before the container's
 * first userspace instruction, so there is no window to skip or tamper with it.
 */
#include <linux/namei.h>

int krunc_landlock_restrict_writes(const char *const *rw_paths, int n_paths);
int krunc_landlock_restrict_writes(const char *const *rw_paths, int n_paths)
{
	const access_mask_t handled =
		LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
		LANDLOCK_ACCESS_FS_REMOVE_DIR | LANDLOCK_ACCESS_FS_REMOVE_FILE |
		LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
		LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK |
		LANDLOCK_ACCESS_FS_MAKE_FIFO | LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		LANDLOCK_ACCESS_FS_MAKE_SYM;
	struct landlock_ruleset *ruleset;
	struct cred *new_cred;
	struct landlock_cred_security *new_llcred;
	struct landlock_ruleset *new_dom;
	int i, err;

	ruleset = landlock_create_ruleset(handled, 0, 0);
	if (IS_ERR(ruleset))
		return PTR_ERR(ruleset);

	for (i = 0; i < n_paths; i++) {
		struct path p;

		/* A writable scratch dir that does not exist is simply skipped. */
		if (kern_path(rw_paths[i], LOOKUP_FOLLOW, &p))
			continue;
		err = landlock_append_fs_rule(ruleset, &p, handled);
		path_put(&p);
		if (err) {
			landlock_put_ruleset(ruleset);
			return err;
		}
	}

	new_cred = prepare_creds();
	if (!new_cred) {
		landlock_put_ruleset(ruleset);
		return -ENOMEM;
	}
	new_llcred = landlock_cred(new_cred);
	/* Merge our ruleset onto any existing domain (NULL for the first layer). */
	new_dom = landlock_merge_ruleset(new_llcred->domain, ruleset);
	landlock_put_ruleset(ruleset);
	if (IS_ERR(new_dom)) {
		abort_creds(new_cred);
		return PTR_ERR(new_dom);
	}
	landlock_put_ruleset(new_llcred->domain);
	new_llcred->domain = new_dom;
	return commit_creds(new_cred);
}
EXPORT_SYMBOL_GPL(krunc_landlock_restrict_writes);
