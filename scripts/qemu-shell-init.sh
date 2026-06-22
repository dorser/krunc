#!/bin/sh
# qemu-shell-init.sh - PID 1 for INTERACTIVE krunc play. Sets up the environment,
# loads the krunc module (creating /dev/krunc), prints a cheatsheet, and drops to
# a shell so you can drive the runtime by hand. Use `poweroff -f` to quit.

PATH=/bin:/sbin:/usr/bin:/usr/sbin
export PATH

/bin/busybox --install -s /bin 2>/dev/null
mount -t proc     proc /proc            2>/dev/null
mount -t sysfs    sys  /sys             2>/dev/null
mount -t devtmpfs dev  /dev             2>/dev/null
mount -t tmpfs    tmp  /tmp             2>/dev/null
mount -t cgroup2  cgrp /sys/fs/cgroup   2>/dev/null

if insmod /krunc.ko 2>/dev/null; then
	echo "krunc.ko loaded -> $(ls -l /dev/krunc 2>/dev/null)"
else
	echo "WARNING: insmod /krunc.ko failed"
fi

cat <<'EOF'

================== krunc interactive shell ==================
Run containers like docker — one command, see the output:

1) docker-run-style one-shot (build + run + wait, confined in-kernel):
     krunc run busybox -- echo hello        # prints: hello
     krunc run busybox -- uname -a
     krunc run busybox -- id                # uid=0(root), but...
     krunc run busybox -- cat /proc/self/status | grep Cap   # all caps dropped
     krunc run busybox -- sh                # interactive shell in a container
   (images live in /images; --name <id> to name it; exit code is propagated.)

2) OCI / runc-compatible CLI (the interface containerd speaks):
     krunc create demo --bundle /bundle    # set up + block before exec
     krunc start  demo                      # release -> exec the entrypoint
     krunc state  demo ; krunc list ; krunc kill demo KILL ; krunc delete demo
   Policy lives in /bundle/config.json (caps, seccomp, Landlock, cgroups,
   user, mounts). Edit it (vi) and re-create to change confinement.

3) Raw kernel text ABI (write a spec line to the control device):
     echo 'run rootfs=/containers/demo host=h exec=/bin/sh arg=/init.sh' > /dev/krunc
     cat /dev/krunc                         # list containers the kernel tracks

Peek at what the kernel enforced (after a container ran):
     ls -l /sys/fs/cgroup/krunc/            # cgroups krunc created
     dmesg | grep -i krunc                  # module log lines

     poweroff -f        # quit QEMU
============================================================
EOF

# Respawn an interactive shell with a controlling tty so job control works; if
# the shell exits, start another (use `poweroff -f` to actually quit).
while true; do
	setsid cttyhack /bin/sh 2>/dev/null || /bin/sh
done
