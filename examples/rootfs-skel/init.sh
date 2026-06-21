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
