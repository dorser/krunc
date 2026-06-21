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

echo "[container] sleeping briefly so the host can inspect our namespaces..."
sleep 3
echo "[container] goodbye (PID 1 exiting -> namespaces tear down)"
echo "=================================================================="
