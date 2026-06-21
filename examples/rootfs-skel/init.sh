#!/bin/sh
# init.sh - entrypoint of the example krunc container (runs as PID 1 inside the
# container's namespaces, after the kernel has chroot'ed us into this rootfs).
#
# It demonstrates the isolation that krunc set up entirely from kernel space.

# The container inherits whatever file descriptors the process that wrote to
# /dev/krunc had, so set up our own /dev and bind stdio to the console. We have
# our own mount namespace (CLONE_NEWNS), so this does not affect the host.
if mount -t devtmpfs dev /dev 2>/dev/null && [ -e /dev/console ]; then
	exec </dev/console >/dev/console 2>/dev/console
else
	exec 1>&2
fi

# Populate busybox applet symlinks (sh was pre-created so we could start).
/bin/busybox --install -s /bin 2>/dev/null

echo "=================================================================="
echo "[container] Hello from inside a krunc container!"
echo "[container] hostname (UTS namespace) : $(hostname)"
echo "[container] my pid   (PID namespace) : $$        <- should be 1"

# A fresh /proc reflects our isolated PID namespace.
mount -t proc proc /proc 2>/dev/null && echo "[container] mounted private /proc"

echo "[container] processes I can see (PID namespace):"
ps -o pid,comm 2>/dev/null || ps

echo "[container] filesystem root (mount ns + chroot):"
ls -1 /

echo "[container] network interfaces (NET namespace):"
if command -v ip >/dev/null 2>&1; then
	ip -o link 2>/dev/null | awk '{print "           " $2}'
else
	ls /sys/class/net 2>/dev/null
fi

echo "[container] writing a file to prove we have our own rootfs..."
echo "krunc was here" > /tmp/krunc-marker 2>/dev/null && cat /tmp/krunc-marker | sed 's/^/[container] /'

echo "[container] sleeping briefly so the host can inspect our namespaces..."
sleep 3
echo "[container] goodbye (PID 1 exiting -> namespaces tear down)"
echo "=================================================================="
