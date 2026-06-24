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
 * Tripwire (demo policy): opening a file whose basename is "krunc-escape". The
 * file_open LSM hook is reached by ordinary, unprivileged opens (unlike
 * mount/module-load, which the capability check rejects before any LSM hook), so
 * it reliably demonstrates the active kill. A real deployment would guard the
 * genuine escape vectors (e.g. lsm/userns_create, lsm/sb_mount, lsm/bpf,
 * lsm/ptrace_access_check) with the same cgroup-keyed mechanism.
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
