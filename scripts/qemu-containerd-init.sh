#!/bin/sh
# qemu-containerd-init.sh - PID 1 for driving krunc through a REAL higher-level
# runtime. Brings up containerd with krunc registered as an OCI runtime, imports
# a busybox image, and drops to a shell so you can `nerdctl run` / `ctr run`
# containers that containerd hands to the krunc kernel domain. `poweroff -f` quits.

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

/bin/busybox --install -s /bin 2>/dev/null
mount -t proc     proc proc /proc          2>/dev/null
mount -t proc     proc /proc               2>/dev/null
mount -t sysfs    sys  /sys                2>/dev/null
mount -t devtmpfs dev  /dev                2>/dev/null
mount -t tmpfs    tmp  /tmp                2>/dev/null
mount -t tmpfs    run  /run                2>/dev/null
mount -t cgroup2  cgrp /sys/fs/cgroup      2>/dev/null
mkdir -p /var/lib/containerd /var/lib/nerdctl /run/containerd /etc/containerd /opt/cni/bin /tmp

if insmod /krunc.ko 2>/dev/null; then
	echo "krunc.ko loaded -> $(ls -l /dev/krunc 2>/dev/null)"
else
	echo "WARNING: insmod /krunc.ko failed"
fi

echo "==> starting containerd (default config)"
containerd >/var/log/containerd.log 2>&1 &
for i in $(seq 1 100); do
	[ -S /run/containerd/containerd.sock ] && break
	sleep 0.2
done
if [ -S /run/containerd/containerd.sock ]; then
	echo "containerd up ($(containerd --version 2>/dev/null | awk '{print $3}'))"
else
	echo "WARNING: containerd socket did not appear; see /var/log/containerd.log"
fi

# Pre-load the busybox image (the guest has no network) into the content store.
# `images import` unpacks into the default (overlayfs) snapshotter, ready to run.
if [ -f /images-archive/busybox-oci.tar ]; then
	if ctr -n default images import /images-archive/busybox-oci.tar >/dev/null 2>&1; then
		echo "imported busybox image"
	else
		echo "WARNING: busybox image import failed"
	fi
fi

cat <<'EOF'

============== krunc + containerd (runc-CLI compatible) ==============
containerd's io.containerd.runc.v2 shim can drive krunc (krunc is the
runc binary). NOTE: krunc is a STRICT OCI runtime — it rejects any
config carrying a property it cannot faithfully apply (per runtime-spec
create). containerd's/nerdctl's DEFAULT configs include a device cgroup,
sysctls and argument-matched seccomp, so these are REJECTED by design
(krunc refuses rather than silently weakening the container):

  nerdctl run --rm --runtime /bin/krunc --net none \
      docker.io/library/busybox:latest echo hi      # -> rejected (exit 1)
  ctr run --rm --runc-binary /bin/krunc \
      docker.io/library/busybox:latest demo echo hi  # -> rejected (exit 1)

To run under containerd the runtime config must be reduced to krunc's
supported subset (or those properties implemented spec-faithfully). For
a working demo, use `krunc run` / a hand-written OCI bundle instead.

Inspect: dmesg | grep krunc   ;   cat /var/log/containerd.log
Quit:    poweroff -f
=====================================================================
EOF

while true; do
	setsid cttyhack /bin/sh 2>/dev/null || /bin/sh
done
