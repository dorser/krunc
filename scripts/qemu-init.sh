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
echo "=========== DEMO 3: OCI runtime CLI (containerd-compatible) ==========="
echo "[vm] krunc --version:"
/bin/krunc --version | sed 's/^/[vm]   /'
echo "[vm] krunc create oci1 --bundle /bundle   (sets up + blocks before exec)"
/bin/krunc create oci1 --bundle /bundle --pid-file /run/oci1.pid
echo "[vm] krunc state oci1   (expect: created)"
/bin/krunc state oci1 | grep -E '"status"|"id"|"pid"' | sed 's/^/[vm]   /'
echo "[vm] krunc start oci1   (releases the paused init -> execs the entrypoint)"
/bin/krunc start oci1
sleep 1
echo "[vm] krunc state oci1   (expect: running)"
/bin/krunc state oci1 | grep -E '"status"|"pid"' | sed 's/^/[vm]   /'
sleep 3
echo "[vm] krunc state oci1   (after the entrypoint exits, expect: stopped)"
/bin/krunc state oci1 | grep -E '"status"' | sed 's/^/[vm]   /'
echo "[vm] krunc list:"
/bin/krunc list | sed 's/^/[vm]   /'
echo "[vm] krunc delete oci1"
/bin/krunc delete oci1

############################################################################
echo
echo "===== DEMO 4: containerd runtime client (go-runc) drives krunc ====="
echo "[vm] go-runc is the library containerd-shim-runc-v2 uses to call the runtime"
if [ -x /bin/krunc-conformance ]; then
	/bin/krunc-conformance /bundle 2>&1 | sed 's/^/[vm]   /'
else
	echo "[vm]   (krunc-conformance not built; skipping)"
fi

############################################################################
echo
echo "================ DEMO 5: unload the runtime cleanly ================"
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
