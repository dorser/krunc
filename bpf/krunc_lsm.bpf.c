// SPDX-License-Identifier: GPL-2.0
/*
 * krunc_lsm.bpf.c - a BPF_PROG_TYPE_LSM program implementing per-container
 * "kill-on-escape" for krunc, attached at runtime (NO kernel source patch).
 *
 * This is krunc's Pillar-2 (lifetime enforcement) active response: krunc applies
 * the namespaces/caps/cgroups/rootfs confinement *at creation*; this BPF-LSM
 * program then continuously guards the running container and KILLS it the moment
 * it attempts a forbidden ("escape") action — something a passive deny (EPERM)
 * cannot do.
 *
 * Scope: a container is guarded iff its cgroup id is present in the `guarded`
 * map. The krunc loader inserts the container's cgroup id between `create` and
 * `start`. bpf_get_current_cgroup_id() identifies the acting task's cgroup, so
 * the policy applies only to that container — never the host or other workloads.
 *
 * Guarded vectors:
 *   - lsm/userns_create: creating a (nested) user namespace — a genuine,
 *     UNPRIVILEGED-reachable privilege-escalation primitive (the starting point of
 *     many container escapes), and, unlike mount/module-load, not blocked by a
 *     capability check before the LSM hook, so guarding it here is meaningful.
 *   - lsm/file_open of a tripwire basename ("krunc-escape"): a controllable demo
 *     hook showing the same cgroup-keyed active-kill mechanism on a file access.
 *
 * Requires only kernel *config* (CONFIG_BPF_SYSCALL, CONFIG_BPF_LSM,
 * CONFIG_DEBUG_INFO_BTF, and "bpf" in CONFIG_LSM) — consistent with krunc's
 * patch-free principle.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

/* cgroup ids krunc has asked us to guard (key = cgroup id, value = 1). */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} guarded SEC(".maps");

/* The tripwire basename whose open triggers the kill. */
#define KRUNC_TRIPWIRE "krunc-escape"

static __always_inline int cgroup_is_guarded(void)
{
	__u64 cgid = bpf_get_current_cgroup_id();

	return bpf_map_lookup_elem(&guarded, &cgid) != NULL;
}

SEC("lsm/userns_create")
int BPF_PROG(krunc_userns_create, const struct cred *cred)
{
	if (!cgroup_is_guarded())
		return 0;

	/* Active response: kill the container trying to create a user namespace,
	 * and deny the operation. */
	bpf_send_signal(9 /* SIGKILL */);
	return -1 /* -EPERM */;
}

SEC("lsm/file_open")
int BPF_PROG(krunc_file_open, struct file *file)
{
	const unsigned char *name;
	char buf[16] = {};

	if (!cgroup_is_guarded())
		return 0;

	name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (!name)
		return 0;
	if (bpf_probe_read_kernel_str(buf, sizeof(buf), name) < 0)
		return 0;

	/* bpf_strncmp returns 0 on an exact match of the first sizeof-1 bytes. */
	if (bpf_strncmp(buf, sizeof(KRUNC_TRIPWIRE) - 1, KRUNC_TRIPWIRE) != 0)
		return 0;

	/* Active response: kill the offending container task, and deny the op. */
	bpf_send_signal(9 /* SIGKILL */);
	return -1 /* -EPERM */;
}
