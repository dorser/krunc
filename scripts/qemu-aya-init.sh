#!/bin/sh
# qemu-aya-init.sh - smoke test for krunc-bpf, the all-Rust (aya) BPF-LSM loader.
# It exercises krunc-bpf init/guard/unguard directly (no CLI yet) against the same
# escape bundle as the libbpf demo, to validate that aya loads the prebuilt
# BPF-LSM object, attaches the LSM programs, pins them, and enforces per-cgroup
# guarding exactly like the C loader it replaces.
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
echo "# krunc-bpf (aya) - BPF-LSM loader smoke test"
echo "# kernel : $(uname -r)"
echo "# LSMs   : $(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "############################################################"

insmod /krunc_helper.ko || { echo "[vm] insmod krunc_helper FAILED"; sleep 1; poweroff -f; }
insmod /krunc.ko        || { echo "[vm] insmod krunc FAILED";        sleep 1; poweroff -f; }

echo "==> krunc create esc --bundle /esc"
/bin/krunc create esc --bundle /esc || { echo "[vm] create FAILED"; sleep 1; poweroff -f; }
CG=/sys/fs/cgroup/krunc/esc
PIN=/sys/fs/bpf/krunc

echo "==> krunc-bpf init  (load + attach + pin the LSM programs/map)"
/bin/krunc-bpf init /krunc_lsm.bpf.o "$PIN" || { echo "[vm] krunc-bpf init FAILED"; sleep 1; poweroff -f; }
echo "==> krunc-bpf init (again, must be idempotent no-op)"
/bin/krunc-bpf init /krunc_lsm.bpf.o "$PIN" || { echo "[vm] krunc-bpf re-init FAILED"; sleep 1; poweroff -f; }
echo "==> krunc-bpf guard $CG block"
/bin/krunc-bpf guard "$PIN" "$CG" block || { echo "[vm] krunc-bpf guard FAILED"; sleep 1; poweroff -f; }
echo "[vm] pinned objects: $(ls /sys/fs/bpf/krunc* 2>/dev/null | tr '\n' ' ')"

echo "==> krunc start esc   (entrypoint attempts unshare(CLONE_NEWUSER))"
/bin/krunc start esc
sleep 1

echo "==> krunc-bpf unguard $CG   (teardown on delete)"
/bin/krunc-bpf unguard "$PIN" "$CG"
/bin/krunc delete esc 2>/dev/null

echo "[vm] PASS = no 'USERNS-CREATED' marker above (escape denied by the aya-loaded"
echo "[vm]        BPF-LSM), the container printed 'STILL RUNNING' (block mode), and"
echo "[vm]        krunc-bpf init/guard/unguard all succeeded."

echo
echo "############ smoke test complete; powering off ############"
sleep 1
poweroff -f
