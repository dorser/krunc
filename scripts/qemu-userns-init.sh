#!/bin/sh
# qemu-userns-init.sh - PID 1 of the QEMU guest for the user-namespace demo.
# krunc creates the container in a new user namespace and writes its uid/gid maps
# (/proc/<pid>/{uid,gid}_map) so that container uid/gid 0 maps to the unprivileged
# host id 100000. The container therefore runs as root *inside* its own user
# namespace while being an ordinary, unprivileged user (100000) on the host — the
# rootless-security property. This proves krunc applies linux.uid/gidMappings.
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
echo "# krunc - user namespaces + uid/gid mappings (rootless-style)"
echo "# kernel : $(uname -r)"
echo "############################################################"

insmod /krunc_helper.ko || { echo "[vm] insmod krunc_helper FAILED"; sleep 1; poweroff -f; }
insmod /krunc.ko        || { echo "[vm] insmod krunc FAILED";        sleep 1; poweroff -f; }
echo "[vm] krunc loaded -> $(ls -l /dev/krunc 2>/dev/null)"

echo
echo "==> krunc create userns --bundle /bundle-userns   (new user ns, maps 0->100000)"
/bin/krunc create userns --bundle /bundle-userns --pid-file /run/userns.pid \
	|| { echo "[vm] create FAILED"; sleep 1; poweroff -f; }
PID=$(cat /run/userns.pid 2>/dev/null)
echo "[vm] container host pid: $PID"

echo "==> krunc start userns   (entrypoint prints its in-container ids)"
/bin/krunc start userns
sleep 1

echo
echo "==> HOST view of the container's init (/proc/$PID/status):"
grep -E '^Uid|^Gid' "/proc/$PID/status" 2>/dev/null | sed 's/^/[host]   /'
echo "==> HOST view of the written map (/proc/$PID/uid_map):"
cat "/proc/$PID/uid_map" 2>/dev/null | sed 's/^/[host]   /'
echo "[vm] PASS = the container printed 'userns-inside uid=0' (root inside its"
echo "[vm]        user ns) while the HOST shows Uid: 100000 (unprivileged), and"
echo "[vm]        uid_map reads '0 100000 65536'."

sleep 3
/bin/krunc delete userns 2>/dev/null

echo
echo "############ demo complete; powering off ############"
sleep 1
poweroff -f
