// SPDX-License-Identifier: GPL-2.0
/*
 * krunc_lsm.bpf.c - a BPF_PROG_TYPE_LSM program implementing per-container
 * per-container "escape blocking" for krunc, attached at runtime (NO kernel
 * source patch).
 *
 * This is krunc's Pillar-2 (lifetime enforcement): krunc applies the
 * namespaces/caps/cgroups/rootfs confinement *at creation*; this BPF-LSM program
 * then continuously guards the running container and responds the moment it
 * attempts a forbidden ("escape") action. The response is per-container policy:
 *   - DENY (default): deny the operation with -EPERM; the container keeps running
 *     (the graceful, Landlock/SELinux-style behavior).
 *   - KILL: additionally SIGKILL the offending container (fail-stop — treat a
 *     container caught attempting an escape as compromised; the seccomp
 *     SCMP_ACT_KILL_PROCESS posture).
 * The loader selects the mode per container (the `guarded` map value).
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
 *   - lsm/sb_mount, lsm/move_mount: mounting / moving mounts (mount-based escapes).
 *   - lsm/bpf: a guarded container loading its own BPF programs/maps.
 *   - lsm/ptrace_access_check: cross-process tracing.
 *   - lsm/file_open of a tripwire basename ("krunc-escape"): a controllable demo
 *     hook showing the same cgroup-keyed mechanism on a file access.
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

/* Guarded cgroups: key = cgroup id, value = enforcement mode for that container.
 * The loader picks the mode; absence from the map = unguarded (policy ignores it). */
#define KRUNC_MODE_DENY 1 /* block: deny the operation (-EPERM); container keeps running */
#define KRUNC_MODE_KILL 2 /* block + SIGKILL the offending container (fail-stop) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, __u64);
	__type(value, __u8);
} guarded SEC(".maps");

/* The tripwire basename guarded by the file_open hook. */
#define KRUNC_TRIPWIRE "krunc-escape"

/* The enforcement mode for the current task's container (0 = unguarded). */
static __always_inline __u8 guard_mode(void)
{
	__u64 cgid = bpf_get_current_cgroup_id();
	__u8 *m = bpf_map_lookup_elem(&guarded, &cgid);

	return m ? *m : 0;
}

/* Enforce the policy on a detected escape attempt: always deny (-EPERM); also
 * SIGKILL the container in KILL mode. Returns 0 (allow) when unguarded. */
static __always_inline int krunc_enforce(__u8 mode)
{
	if (mode == 0)
		return 0;
	if (mode >= KRUNC_MODE_KILL)
		bpf_send_signal(9 /* SIGKILL */);
	return -1 /* -EPERM */;
}

SEC("lsm/userns_create")
int BPF_PROG(krunc_userns_create, const struct cred *cred)
{
	/* deny (and, in KILL mode, kill) a guarded container creating a user ns. */
	return krunc_enforce(guard_mode());
}

/* Other real escape/abuse vectors a guarded container has no business using.
 * krunc's own setup mounts run during `create`, before the loader adds the
 * container to the `guarded` map, so they are never affected by these hooks. */

SEC("lsm/sb_mount")
int BPF_PROG(krunc_sb_mount)
{
	/* mounting is a classic escape primitive (e.g. remounting over host paths). */
	return krunc_enforce(guard_mode());
}

SEC("lsm/move_mount")
int BPF_PROG(krunc_move_mount)
{
	return krunc_enforce(guard_mode());
}

SEC("lsm/bpf")
int BPF_PROG(krunc_bpf)
{
	/* a guarded container loading its own BPF is a privilege/abuse vector. */
	return krunc_enforce(guard_mode());
}

SEC("lsm/ptrace_access_check")
int BPF_PROG(krunc_ptrace)
{
	/* cross-process tracing inside the container's pid ns is allowed; this only
	 * fires for a guarded container, and denies tracing as a hardening measure. */
	return krunc_enforce(guard_mode());
}

SEC("lsm/file_open")
int BPF_PROG(krunc_file_open, struct file *file)
{
	const unsigned char *name;
	char buf[16] = {};
	__u8 mode = guard_mode();

	if (mode == 0)
		return 0;

	name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
	if (!name)
		return 0;
	if (bpf_probe_read_kernel_str(buf, sizeof(buf), name) < 0)
		return 0;

	/* bpf_strncmp returns 0 on an exact match of the first sizeof-1 bytes. */
	if (bpf_strncmp(buf, sizeof(KRUNC_TRIPWIRE) - 1, KRUNC_TRIPWIRE) != 0)
		return 0;

	/* deny (and, in KILL mode, kill) the tripwire access. */
	return krunc_enforce(mode);
}
