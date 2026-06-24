#!/bin/sh
# init.sh - entrypoint of the example krunc container (runs as PID 1 inside the
# container's namespaces, after the kernel set it up and dropped privileges).
#
# Output goes to the inherited stderr (the console) via `exec 1>&2`, which works
# whether or not the container is privileged enough to set up its own /dev.

exec 1>&2
/bin/busybox --install -s /bin 2>&-

echo "=================================================================="
echo "[container] Hello from inside a krunc container!"
echo "[container] hostname (UTS namespace) : $(hostname)"
echo "[container] my pid   (PID namespace) : $$        <- should be 1"

# The kernel mounts a private /proc for us (before dropping privileges), so even
# a fully confined container has one without needing CAP_SYS_ADMIN itself.
if [ -r /proc/self/status ]; then
	echo "[container] /proc available (kernel-mounted)"
	echo "[container] CapBnd=$(awk '/^CapBnd:/{print $2}' /proc/self/status)" \
	     "CapEff=$(awk '/^CapEff:/{print $2}' /proc/self/status)" \
	     "NoNewPrivs=$(awk '/^NoNewPrivs:/{print $2}' /proc/self/status)"
	echo "[container] processes I can see (PID namespace):"
	ps -o pid,comm 2>&- || ps 2>&-
else
	echo "[container] /proc not available"
fi

echo "[container] filesystem root (mount ns + chroot):"
ls -1 / 2>&-
echo "[container] network interfaces (NET namespace):"
if ip -o link 2>&-; then :; else ls /sys/class/net 2>&-; fi

# pids cgroup limit test: try to spawn many background processes. If the cgroup
# pids.max is enforced, only that many will start. They stay alive (sleep) so the
# host can read pids.current.
if [ "$KRUNC_PIDS_TEST" = 1 ]; then
	echo "[container] --- filesystem confinement (masked + read-only paths) ---"
	# masked: /proc/kcore is normally a full image of kernel memory; krunc
	# over-mounts it with /dev/null so it reads as empty (no info leak).
	echo "[container]   masked /proc/kcore size: $(wc -c < /proc/kcore 2>&-) bytes (expect 0)"
	# masked: writing 'c' to /proc/sysrq-trigger crashes the host -- a classic
	# escape. It is masked, so the write lands in /dev/null and is inert.
	if echo 0 >/proc/sysrq-trigger 2>/dev/null; then
		echo "[container]   /proc/sysrq-trigger write: inert (masked by /dev/null)"
	else
		echo "[container]   /proc/sysrq-trigger write: denied"
	fi
	# read-only: writes fail with EROFS even though we are uid 0. /proc/sys being
	# read-only blocks core_pattern-style escapes; /etc shows a plain write deny.
	touch /etc/should-not-exist 2>/dev/null
	if [ -e /etc/should-not-exist ]; then
		echo "[container]   /etc: WRITABLE (unexpected)"
	else
		echo "[container]   /etc: read-only, write denied (EROFS)"
	fi
	touch /proc/sys/kernel/should-not-exist 2>/dev/null
	if [ -e /proc/sys/kernel/should-not-exist ]; then
		echo "[container]   /proc/sys: WRITABLE (unexpected)"
	else
		echo "[container]   /proc/sys: read-only, write denied (EROFS)"
	fi
	# read-only rootfs (root.readonly): the kernel bind-mounts the rootfs and
	# remounts it read-only, so its files are immutable even to uid 0, while a
	# writable mount like /tmp (a separate mount on top) stays writable.
	touch /should-not-exist 2>/dev/null
	if [ -e /should-not-exist ]; then
		echo "[container]   rootfs / : WRITABLE (unexpected)"
	else
		echo "[container]   rootfs / : read-only, write denied (EROFS)"
	fi
	if touch /tmp/krunc-ok 2>/dev/null; then
		echo "[container]   /tmp    : writable (scratch mount stays rw)"
	else
		echo "[container]   /tmp    : NOT writable (unexpected)"
	fi

	echo "[container] --- sysctls (linux.sysctl applied by the kernel) ---"
	echo "[container]   net.ipv4.ip_forward = $(cat /proc/sys/net/ipv4/ip_forward 2>&-)  (config requests 1)"

	echo "[container] --- resource limits (rlimits / oom) ---"
	echo "[container]   RLIMIT_NOFILE (ulimit -n) = $(ulimit -n)  (config soft=256)"

	echo "[container] --- user (process.user) ---"
	echo "[container]   running as uid:gid = $(id -u):$(id -g)  (config requests 65534:65534)"

	echo "[container] --- mounts (OCI mounts[] applied by the kernel) ---"
	echo "[container]   /tmp: $(awk '$2=="/tmp"{print $1,$3,$4}' /proc/mounts 2>&-)  (expect tmpfs, nosuid/nodev/noexec)"

	echo "[container] --- memory cgroup limit (memory.max) ---"
	echo "[container]   memhog allocates until the cgroup OOM-kills it (config max=64 MiB):"
	/bin/memhog
	echo "[container]   memhog returned -- it was OOM-killed by the cgroup at memory.max"

	echo "[container] --- cpu cgroup limit (cpu.max) ---"
	echo "[container]   cpuhog runs a CPU-bound loop; the cgroup throttles it to the quota (10%):"
	/bin/cpuhog

	echo "[container] my cgroup: $(cat /proc/self/cgroup 2>&-)"
	echo "[container] pids test: forktest will fork until the cgroup pids.max stops it"
	# Hand off to the deterministic fork(2) probe. It becomes PID 1, forks until
	# the cgroup denies it, then keeps every survivor alive (each pause(2)s) so
	# the host can read pids.current == pids.max; the host stops us via 'krunc kill'.
	exec /bin/forktest
fi

echo "[container] sleeping briefly so the host can inspect our namespaces..."
sleep 3
echo "[container] goodbye (PID 1 exiting -> namespaces tear down)"
echo "=================================================================="
