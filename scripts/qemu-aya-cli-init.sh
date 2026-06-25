#!/bin/sh
# qemu-aya-cli-init.sh - end-to-end demo of CLI-driven, per-container BPF-LSM.
# Unlike the manual loader demos, here the `krunc` CLI itself arms the aya
# BPF-LSM policy at `create` (because the bundle carries the annotation
# org.krunc.bpf-lsm=block) and tears it down at `delete` — folding the loader
# into the container lifecycle. The escape (unshare CLONE_NEWUSER) is denied
# while the container keeps running; after delete the cgroup is un-guarded.
exec 1>&2
PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH
/bin/busybox --install -s /bin 2>/dev/null
mount -t proc     proc /proc           2>/dev/null
mount -t sysfs    sys  /sys             2>/dev/null
mount -t cgroup2  cgrp /sys/fs/cgroup   2>/dev/null
mkdir -p /sys/fs/bpf
mount -t bpf      bpf  /sys/fs/bpf      2>/dev/null
mount -t devtmpfs dev  /dev             2>/dev/null
mount -t tmpfs    tmp  /tmp             2>/dev/null
mount -t securityfs sec /sys/kernel/security 2>/dev/null

echo "############################################################"
echo "# krunc - CLI-driven per-container BPF-LSM (aya, lifecycle)"
echo "# kernel : $(uname -r)"
echo "############################################################"

insmod /krunc_helper.ko || { echo "[vm] insmod krunc_helper FAILED"; sleep 1; poweroff -f; }
insmod /krunc.ko        || { echo "[vm] insmod krunc FAILED";        sleep 1; poweroff -f; }

# The CLI finds krunc-bpf on PATH and the BPF object at /krunc_lsm.bpf.o.
echo "==> krunc create esc-cli --bundle /esc-cli   (CLI arms BPF-LSM from the annotation)"
/bin/krunc create esc-cli --bundle /esc-cli || { echo "[vm] create FAILED"; sleep 1; poweroff -f; }
CG=/sys/fs/cgroup/krunc/esc-cli
echo "[vm] guarded map entries (cgroup id $(stat -c %i "$CG" 2>/dev/null) expected):"
bpftool map dump pinned /sys/fs/bpf/krunc/guarded 2>/dev/null | sed 's/^/[vm]   /' || \
	echo "[vm]   (bpftool unavailable; pins: $(ls /sys/fs/bpf/krunc 2>/dev/null | tr '\n' ' '))"

echo "==> krunc start esc-cli   (entrypoint attempts unshare(CLONE_NEWUSER))"
/bin/krunc start esc-cli
sleep 1

echo "==> krunc delete esc-cli   (CLI un-guards the cgroup)"
/bin/krunc delete esc-cli

echo "[vm] PASS = the container printed 'DENIED by BPF-LSM' + 'STILL RUNNING'"
echo "[vm]        (CLI-armed block-mode escape blocking), with no manual loader call."

echo
echo "############ demo complete; powering off ############"
sleep 1
poweroff -f
