#!/bin/sh
# qemu-init.sh - PID 1 of the QEMU test VM (the initramfs /init). It exercises
# the krunc kernel container runtime end to end:
#   1. load the module, get /dev/krunc
#   2. launch an isolated container and verify, from the host side, that the
#      kernel created real namespaces
#   3. launch a long-running container and stop it with `kill`
#   4. unload the module cleanly
#
# This is the *host* side of the demo; examples/rootfs-skel/init.sh is the
# *container* side.

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
echo "# krunc - a container runtime in the kernel"
echo "# kernel        : $(uname -r)"
echo "# host hostname : $(hostname)"
echo "##################################################################"

echo "[vm] loading krunc.ko ..."
insmod /krunc.ko || { echo "[vm] insmod FAILED"; sleep 2; poweroff -f; }
echo "[vm] loaded; control device: $(ls -l /dev/krunc 2>/dev/null)"

# Keep the control device open on fd 3 for all our writes.
exec 3>/dev/krunc

############################################################################
echo
echo "================ DEMO 1: launch an isolated container ================"
SPEC='run rootfs=/containers/demo host=krunc-demo exec=/bin/sh arg=/init.sh'
echo "[vm] echo \"$SPEC\" > /dev/krunc"
echo "$SPEC" >&3
sleep 1

CPID=$(cat /dev/krunc | awk '/krunc-demo/{print $2; exit}')
echo "[vm] container started with host-visible pid: ${CPID:-<none>}"
if [ -n "$CPID" ] && [ -e "/proc/$CPID/ns/pid" ]; then
	echo "[vm] --- namespace isolation (host view of pid $CPID) ---"
	for ns in pid mnt uts ipc net; do
		H=$(readlink "/proc/self/ns/$ns")
		C=$(readlink "/proc/$CPID/ns/$ns")
		if [ "$H" != "$C" ]; then
			echo "[vm]   $ns: ISOLATED  (host $H vs container $C)"
		else
			echo "[vm]   $ns: shared $H"
		fi
	done
fi
# let the container print its side and exit
sleep 3

############################################################################
echo
echo "============ DEMO 2: launch + kill a long-running container ============"
SPEC2='run rootfs=/containers/demo host=sleeper exec=/bin/busybox arg=sleep arg=600'
echo "[vm] echo \"$SPEC2\" > /dev/krunc"
echo "$SPEC2" >&3
sleep 1
echo "[vm] container table:"
cat /dev/krunc | sed 's/^/[vm]   /'
SPID=$(cat /dev/krunc | awk '/sleeper/{print $2; exit}')
echo "[vm] stopping sleeper (pid $SPID): echo \"kill $SPID\" > /dev/krunc"
echo "kill $SPID" >&3
sleep 1
echo "[vm] container table after kill:"
cat /dev/krunc | sed 's/^/[vm]   /'

############################################################################
echo
echo "====== DEMO 3: OCI lifecycle via the all-Rust krunc CLI + confinement ======"
echo "[vm] krunc --version:"
/bin/krunc --version | sed 's/^/[vm]   /'
echo "[vm] krunc create oci1 --bundle /bundle   (sets up + blocks before exec)"
/bin/krunc create oci1 --bundle /bundle --pid-file /run/oci1.pid
CPID=$(cat /run/oci1.pid 2>/dev/null)
echo "[vm] krunc state oci1   (expect: created)"
/bin/krunc state oci1 | grep -E '"status"|"id"|"pid"' | sed 's/^/[vm]   /'
echo "[vm] krunc start oci1   (releases the paused init -> execs the entrypoint)"
/bin/krunc start oci1
sleep 1
echo "[vm] krunc state oci1   (expect: running)"
/bin/krunc state oci1 | grep -E '"status"|"pid"' | sed 's/^/[vm]   /'
echo "[vm] ----- kernel-applied confinement, host view of /proc/$CPID/status -----"
grep -E "^(CapBnd|CapPrm|CapEff|NoNewPrivs|Seccomp|Uid|Gid):" /proc/$CPID/status 2>/dev/null | sed 's/^/[vm]   /'
echo "[vm]   expected: CapBnd 00000000200004e1 (6 bounded), CapEff/CapPrm 0 (none granted), NoNewPrivs 1, Seccomp 2, Uid/Gid 65534"
echo "[vm]   RLIMIT_NOFILE: $(grep -E '^Max open files' /proc/$CPID/limits 2>/dev/null)   (expect soft 256 hard 512)"
echo "[vm]   oom_score_adj = $(cat /proc/$CPID/oom_score_adj 2>/dev/null)   (expect -500)"
# Give the container's probes time to run (memhog OOM ~1s, cpuhog ~3s) and the
# forktest probe to fork up to the cap and park. Its parent and every survivor
# pause(), so this snapshot is stable. The cgroup event counters (memory
# oom_kill, cpu throttling) are cumulative and persist after the probes exit.
sleep 7
echo "[vm] ----- cgroup pids limit (host view of the container's cgroup) -----"
PMAX=$(cat /sys/fs/cgroup/krunc/oci1/pids.max 2>/dev/null)
PCUR=$(cat /sys/fs/cgroup/krunc/oci1/pids.current 2>/dev/null)
PEVT=$(cat /sys/fs/cgroup/krunc/oci1/pids.events 2>/dev/null | tr '\n' ' ')
PEVT_MAX=$(awk '/^max /{print $2}' /sys/fs/cgroup/krunc/oci1/pids.events 2>/dev/null)
echo "[vm]   pids.max     = $PMAX"
echo "[vm]   pids.current = $PCUR   (forktest tried to fork past the limit; the kernel capped it)"
echo "[vm]   pids.events  = $PEVT   (max = number of forks the kernel denied)"
if [ "${PEVT_MAX:-0}" -gt 0 ] && [ "$PCUR" = "$PMAX" ]; then
	echo "[vm]   RESULT: pids cgroup ENFORCED -- kernel denied ${PEVT_MAX} forks; pids.current pinned at pids.max=$PMAX"
else
	echo "[vm]   RESULT: pids.current=$PCUR pids.max=$PMAX denials=${PEVT_MAX:-0} (expected current==max with denials>0)"
fi
echo "[vm] ----- cgroup memory limit (host view of the container's cgroup) -----"
MMAX=$(cat /sys/fs/cgroup/krunc/oci1/memory.max 2>/dev/null)
MEVT=$(cat /sys/fs/cgroup/krunc/oci1/memory.events 2>/dev/null | tr '\n' ' ')
MOOMK=$(awk '/^oom_kill /{print $2}' /sys/fs/cgroup/krunc/oci1/memory.events 2>/dev/null)
echo "[vm]   memory.max    = $MMAX   (= 64 MiB)"
echo "[vm]   memory.events = $MEVT"
if [ "${MOOMK:-0}" -gt 0 ]; then
	echo "[vm]   RESULT: memory cgroup ENFORCED -- kernel OOM-killed ${MOOMK} process(es) at memory.max"
else
	echo "[vm]   RESULT: memory.max=$MMAX oom_kill=${MOOMK:-0} (expected oom_kill>0 from memhog)"
fi
echo "[vm] ----- cgroup cpu limit (host view of the container's cgroup) -----"
CMAX=$(cat /sys/fs/cgroup/krunc/oci1/cpu.max 2>/dev/null)
CTHR=$(awk '/^nr_throttled /{print $2}' /sys/fs/cgroup/krunc/oci1/cpu.stat 2>/dev/null)
CTUS=$(awk '/^throttled_usec /{print $2}' /sys/fs/cgroup/krunc/oci1/cpu.stat 2>/dev/null)
echo "[vm]   cpu.max = $CMAX   (= 10% of one CPU: 10000us quota / 100000us period)"
echo "[vm]   cpu.stat: nr_throttled=$CTHR throttled_usec=$CTUS"
if [ "${CTHR:-0}" -gt 0 ]; then
	echo "[vm]   RESULT: cpu cgroup ENFORCED -- the kernel throttled the cgroup ${CTHR} time(s)"
else
	echo "[vm]   RESULT: nr_throttled=${CTHR:-0} (expected >0 from cpuhog)"
fi
echo "[vm] krunc kill oci1   (forktest is parked as PID 1; stop the whole tree)"
/bin/krunc kill oci1 KILL
sleep 1
echo "[vm] krunc state oci1   (after kill, expect: stopped)"
/bin/krunc state oci1 | grep -E '"status"' | sed 's/^/[vm]   /'
echo "[vm] krunc list:"
/bin/krunc list | sed 's/^/[vm]   /'
echo "[vm] krunc delete oci1"
/bin/krunc delete oci1

############################################################################
echo
echo "================ DEMO 4: unload the runtime cleanly ================"
exec 3>&-                 # close the control device so the module is unused
if rmmod krunc; then
	echo "[vm] krunc.ko unloaded cleanly"
	if [ -e /dev/krunc ]; then
		echo "[vm]   /dev/krunc still present?!"
	else
		echo "[vm]   /dev/krunc removed"
	fi
else
	echo "[vm] rmmod FAILED"
fi

echo
echo "[vm] all demos complete; powering off."
sleep 1
poweroff -f
