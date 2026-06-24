#!/bin/sh
# qemu-bpflsm-init.sh - PID 1 of the QEMU guest for the M8 BPF-LSM kill-on-escape
# demo. It loads krunc, arms a per-container BPF-LSM policy on the container's
# cgroup, starts the container, and shows the container is KILLED the instant it
# opens the tripwire file -- an active response (not just a passive deny) that
# krunc could not do after dropping seccomp. All patch-free: the kernel only
# needs CONFIG_BPF_LSM + BTF (+ "bpf" in CONFIG_LSM), no source patch.
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
echo "# krunc M8 - BPF-LSM per-container kill-on-escape (patch-free)"
echo "# kernel : $(uname -r)"
echo "# LSMs   : $(cat /sys/kernel/security/lsm 2>/dev/null)"
echo "############################################################"

insmod /krunc_helper.ko || { echo "[vm] insmod krunc_helper FAILED"; sleep 1; poweroff -f; }
insmod /krunc.ko        || { echo "[vm] insmod krunc FAILED";        sleep 1; poweroff -f; }
echo "[vm] krunc loaded -> $(ls -l /dev/krunc 2>/dev/null)"

# 1. Create the container: krunc makes its cgroup (krunc/esc) and blocks PID 1
#    before exec, so we can arm the policy before the entrypoint runs.
echo
echo "==> krunc create esc --bundle /esc   (creates cgroup, blocks before exec)"
/bin/krunc create esc --bundle /esc || { echo "[vm] create FAILED"; sleep 1; poweroff -f; }
CG=/sys/fs/cgroup/krunc/esc
echo "[vm] container cgroup: $CG (id $(stat -c %i "$CG" 2>/dev/null))"

# 2. Arm the BPF-LSM kill-on-escape for THIS container's cgroup only.
echo
echo "==> arm BPF-LSM on the container cgroup"
/bin/krunc_lsm_loader /krunc_lsm.bpf.o "$CG" /sys/fs/bpf/krunc_lsm \
	|| { echo "[vm] loader FAILED"; sleep 1; poweroff -f; }

# 3. Start the container -> its PID 1 opens the tripwire -> BPF-LSM kills it.
echo
echo "==> krunc start esc   (entrypoint opens /krunc-escape)"
/bin/krunc start esc
sleep 1

# 4. Verdict. The container must be stopped, and the tripwire's content
#    ("ESCAPE-SUCCEEDED...") must NOT have been printed above (it is only printed
#    if the open was allowed, i.e. the BPF-LSM did not deny+kill).
echo
echo "==> verdict"
echo "[vm] krunc state esc:"
/bin/krunc state esc 2>/dev/null | grep -E '"status"|"id"' | sed 's/^/[vm]   /'
echo "[vm] PASS = status 'stopped' AND the tripwire file's contents were NOT"
echo "[vm]        printed above (the container's PID 1 was SIGKILL'd at open(2),"
echo "[vm]        so it never read the file). A printed tripwire line = FAIL."
/bin/krunc delete esc 2>/dev/null

echo
echo "############ demo complete; powering off ############"
sleep 1
poweroff -f
