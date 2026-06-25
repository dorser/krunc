// SPDX-License-Identifier: GPL-2.0
/*
 * krunc_lsm_loader.c - load + attach krunc's BPF-LSM kill-on-escape program and
 * mark a container's cgroup as guarded. Runs in the (host) init context between
 * `krunc create` and `krunc start`, so the policy is in force before the
 * container's entrypoint executes.
 *
 *   krunc_lsm_loader <krunc_lsm.bpf.o> <cgroup-dir> <link-pin-path>
 *     e.g. krunc_lsm_loader /krunc_lsm.bpf.o /sys/fs/cgroup/krunc/oci1 \
 *                           /sys/fs/bpf/krunc_lsm
 *
 * It pins the attach link so the program stays attached after this process
 * exits, then inserts the container's cgroup id (cgroup v2: the cgroup directory
 * inode number, which is what bpf_get_current_cgroup_id() returns) into the
 * `guarded` map.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

int main(int argc, char **argv)
{
	if (argc != 4 && argc != 5) {
		fprintf(stderr,
			"usage: %s <bpf.o> <cgroup-dir> <link-pin> [block|kill]\n"
			"  block (default): deny escapes with -EPERM, container keeps running\n"
			"  kill           : also SIGKILL the container on an escape attempt\n",
			argv[0]);
		return 2;
	}
	const char *obj_path = argv[1];
	const char *cgroup_dir = argv[2];
	const char *pin_path = argv[3];
	const char *mode_arg = (argc == 5) ? argv[4] : "block";

	/* enforcement mode stored as the `guarded` map value (see krunc_lsm.bpf.c). */
	__u8 mode;
	if (strcmp(mode_arg, "block") == 0) {
		mode = 1; /* KRUNC_MODE_DENY */
	} else if (strcmp(mode_arg, "kill") == 0) {
		mode = 2; /* KRUNC_MODE_KILL */
	} else {
		fprintf(stderr, "invalid mode '%s' (expected block|kill)\n", mode_arg);
		return 2;
	}

	struct stat st;
	if (stat(cgroup_dir, &st)) {
		fprintf(stderr, "stat(%s): %s\n", cgroup_dir, strerror(errno));
		return 1;
	}
	__u64 cgid = (__u64)st.st_ino; /* cgroup v2 id == cgroup dir inode */

	struct bpf_object *obj = bpf_object__open_file(obj_path, NULL);
	if (!obj || libbpf_get_error(obj)) {
		fprintf(stderr, "open %s failed\n", obj_path);
		return 1;
	}
	if (bpf_object__load(obj)) {
		fprintf(stderr, "load failed: %s\n", strerror(errno));
		return 1;
	}

	/* Attach every LSM program in the object (one per guarded vector) and pin
	 * each link so the policy persists after this loader exits. */
	struct bpf_program *prog;
	int n_attached = 0;
	bpf_object__for_each_program(prog, obj) {
		const char *pname = bpf_program__name(prog);
		struct bpf_link *link = bpf_program__attach(prog);
		if (!link || libbpf_get_error(link)) {
			fprintf(stderr, "attach %s failed: %s\n", pname, strerror(errno));
			return 1;
		}
		char pin[512];
		snprintf(pin, sizeof(pin), "%s_%s", pin_path, pname);
		if (bpf_link__pin(link, pin)) {
			fprintf(stderr, "pin %s: %s\n", pin, strerror(errno));
			return 1;
		}
		n_attached++;
	}
	if (n_attached == 0) {
		fprintf(stderr, "no programs to attach\n");
		return 1;
	}

	int mapfd = bpf_object__find_map_fd_by_name(obj, "guarded");
	if (mapfd < 0) {
		fprintf(stderr, "map 'guarded' not found\n");
		return 1;
	}
	if (bpf_map_update_elem(mapfd, &cgid, &mode, BPF_ANY)) {
		fprintf(stderr, "map update: %s\n", strerror(errno));
		return 1;
	}

	printf("krunc_lsm: guarding cgroup %s (id %llu) in %s mode; %d hooks armed\n",
	       cgroup_dir, (unsigned long long)cgid, mode_arg, n_attached);
	return 0;
}
