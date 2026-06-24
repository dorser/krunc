#!/bin/sh
# qemu-conformance-init.sh - PID 1 for an OCI conformance run under QEMU. It
# loads krunc.ko and launches the official opencontainers/runtime-tools
# `runtimetest` binary as a container via the runc-compatible krunc CLI.
# runtimetest reads the bundle's config.json from its cwd ("/") and compares the
# live container environment against it, emitting TAP (ok / not ok) results.
#
# This gives an objective, external conformance signal for the subset of the OCI
# runtime-spec that krunc implements (the config used here stays within that
# subset; properties krunc rejects are not present). The initramfs is assembled
# by make-initramfs.sh with RUNTIMETEST pointing at a built runtimetest binary.

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

/bin/busybox --install -s /bin 2>/dev/null
mount -t proc     proc /proc 2>/dev/null
mount -t sysfs    sys  /sys  2>/dev/null
mount -t devtmpfs dev  /dev  2>/dev/null
mount -t tmpfs    tmp  /tmp  2>/dev/null
mount -t cgroup2  cgrp /sys/fs/cgroup 2>/dev/null

echo
echo "##################################################################"
echo "# krunc - OCI runtime-tools conformance (runtimetest)"
echo "# kernel : $(uname -r)"
echo "##################################################################"

if [ ! -d /conformance ]; then
	echo "[vm] no /conformance bundle (build initramfs with RUNTIMETEST=<path>)"
	poweroff -f
fi

echo "[vm] loading krunc.ko ..."
insmod /krunc_helper.ko || { echo "[vm] insmod krunc_helper FAILED"; sleep 2; poweroff -f; }
insmod /krunc.ko || { echo "[vm] insmod FAILED"; sleep 2; poweroff -f; }
echo "[vm] /dev/krunc: $(ls -l /dev/krunc 2>/dev/null)"

echo "[vm] krunc create conf --bundle /conformance"
/bin/krunc create conf --bundle /conformance || { echo "[vm] create FAILED"; sleep 1; poweroff -f; }
echo "[vm] krunc start conf   (runtimetest runs inside; TAP output follows)"
echo "------------------------------- runtimetest TAP -------------------------------"
/bin/krunc start conf

# Wait for runtimetest (the container init) to exit.
i=0
while [ "$i" -lt 40 ]; do
	st=$(/bin/krunc state conf 2>/dev/null | grep -o '"status"[^,]*')
	case "$st" in *stopped*) break ;; esac
	sleep 0.25
	i=$((i + 1))
done
echo "-------------------------------------------------------------------------------"
/bin/krunc state conf 2>/dev/null | grep -o '"status"[^,]*' | sed 's/^/[vm] final container state: /'
/bin/krunc delete conf 2>/dev/null

echo "[vm] conformance run complete; powering off."
sleep 1
poweroff -f
