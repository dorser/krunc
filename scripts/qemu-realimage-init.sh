#!/bin/sh
# qemu-realimage-init.sh - PID 1 of the QEMU guest for the "real OCI image" demo.
# It loads krunc and runs a real, unmodified Alpine Linux userland (musl libc,
# busybox, /etc/apk, the actual distro filesystem extracted from the official
# alpine-minirootfs image) as a krunc container via the docker-style `krunc run`.
# This proves krunc runs genuine distribution images end-to-end, not just the
# hand-built busybox demo rootfs, while still applying its full confinement
# (dropped caps, no_new_privs, fresh namespaces, read-only /proc/sys, cgroup
# limits). The rootfs is staged at /alpine by make-initramfs.sh (ALPINE_ROOTFS=).
exec 1>&2
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc     proc /proc           2>/dev/null
mount -t sysfs    sys  /sys             2>/dev/null
mount -t cgroup2  cgrp /sys/fs/cgroup   2>/dev/null
mount -t devtmpfs dev  /dev             2>/dev/null
mount -t tmpfs    tmp  /tmp             2>/dev/null

echo "############################################################"
echo "# krunc - run a REAL OCI image (Alpine Linux) end-to-end"
echo "# kernel : $(uname -r)"
echo "############################################################"

insmod /krunc_helper.ko || { echo "[vm] insmod krunc_helper FAILED"; sleep 1; poweroff -f; }
insmod /krunc.ko        || { echo "[vm] insmod krunc FAILED";        sleep 1; poweroff -f; }
echo "[vm] krunc loaded -> $(ls -l /dev/krunc 2>/dev/null)"

if [ ! -x /alpine/bin/busybox ] && [ ! -e /alpine/etc/alpine-release ]; then
	echo "[vm] no Alpine rootfs staged at /alpine (set ALPINE_ROOTFS=); skipping"
	sleep 1; poweroff -f
fi

# Run the real Alpine userland confined by krunc. The entrypoint prints the
# distro identity (proving it is the genuine image), the effective uid/caps
# (proving confinement applied), and that /proc is mounted in the container.
echo
echo "==> krunc run --rootfs /alpine -- /bin/sh -c '<probe>'"
/bin/krunc run --name alpine --rootfs /alpine -- /bin/sh -c '
	echo "[alpine] os-release:"; cat /etc/os-release | sed "s/^/[alpine]   /"
	echo "[alpine] alpine-release: $(cat /etc/alpine-release 2>/dev/null)"
	echo "[alpine] whoami uid=$(id -u) gid=$(id -g)"
	echo "[alpine] apk index present: $([ -d /etc/apk ] && echo yes || echo no)"
	echo "[alpine] hostname=$(hostname)"
	echo "[alpine] /proc mounted: $([ -e /proc/self/status ] && echo yes || echo no)"
	echo "[alpine] CapEff=$(grep CapEff /proc/self/status | awk "{print \$2}")"
	echo "[alpine] NoNewPrivs=$(grep NoNewPrivs /proc/self/status | awk "{print \$2}")"
	echo "ALPINE-RAN-OK"
'
RC=$?
echo "[vm] krunc run exit code: $RC"
echo "[vm] PASS = output shows 'Alpine Linux' (real image ran), CapEff=0000000000000000"
echo "[vm]        (caps dropped), NoNewPrivs=1, and 'ALPINE-RAN-OK' with exit code 0."

echo
echo "############ demo complete; powering off ############"
sleep 1
poweroff -f
