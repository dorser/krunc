#!/usr/bin/env bash
# make-initramfs.sh - assemble a minimal initramfs containing busybox, the krunc
# module, the QEMU init, and an example container rootfs.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
OUT="${OUT:-$HOME/krunc-initramfs.cpio.gz}"
BB="$(command -v busybox || echo /bin/busybox)"
[ -x "$BB" ] || { echo "busybox-static not found (apt install busybox-static)"; exit 1; }
[ -f "$REPO/module/krunc.ko" ] || { echo "build krunc.ko first (scripts/build-module.sh)"; exit 1; }
KRUNC_BIN="$REPO/userspace/target/x86_64-unknown-linux-musl/release/krunc"
[ -x "$KRUNC_BIN" ] || { echo "build the CLI first (scripts/build-cli.sh)"; exit 1; }

ROOT="$(mktemp -d)"
cleanup() { sudo rm -rf "$ROOT"; }
trap cleanup EXIT

# directory skeleton
mkdir -p "$ROOT"/bin "$ROOT"/sbin "$ROOT"/proc "$ROOT"/sys "$ROOT"/dev "$ROOT"/tmp "$ROOT"/run
mkdir -p "$ROOT"/containers/demo/bin "$ROOT"/containers/demo/proc \
         "$ROOT"/containers/demo/sys "$ROOT"/containers/demo/dev \
         "$ROOT"/containers/demo/tmp
# OCI bundle (config.json + rootfs) for the runc-compatible CLI demo
mkdir -p "$ROOT"/bundle/rootfs/bin "$ROOT"/bundle/rootfs/proc \
         "$ROOT"/bundle/rootfs/sys "$ROOT"/bundle/rootfs/dev "$ROOT"/bundle/rootfs/tmp \
         "$ROOT"/bundle/rootfs/etc

# initramfs userland
cp "$BB" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
cp "$REPO/scripts/qemu-init.sh" "$ROOT/init"
cp "$REPO/module/krunc.ko" "$ROOT/krunc.ko"
cp "$KRUNC_BIN" "$ROOT/bin/krunc"
chmod +x "$ROOT/init" "$ROOT/bin/busybox" "$ROOT/bin/krunc"

# example container rootfs (text interface)
cp "$BB" "$ROOT/containers/demo/bin/busybox"
ln -sf busybox "$ROOT/containers/demo/bin/sh"
cp "$REPO/examples/rootfs-skel/init.sh" "$ROOT/containers/demo/init.sh"
chmod +x "$ROOT/containers/demo/init.sh" "$ROOT/containers/demo/bin/busybox"

# OCI bundle rootfs (same busybox app) + config.json
cp "$BB" "$ROOT/bundle/rootfs/bin/busybox"
ln -sf busybox "$ROOT/bundle/rootfs/bin/sh"
cp "$REPO/examples/rootfs-skel/init.sh" "$ROOT/bundle/rootfs/init.sh"
cp "$REPO/examples/bundle/config.json" "$ROOT/bundle/config.json"
chmod +x "$ROOT/bundle/rootfs/init.sh" "$ROOT/bundle/rootfs/bin/busybox"

# Pre-install the busybox applet symlinks at build time so the bundle works when
# the container runs as a non-root user (config.json sets process.user), which
# cannot write the root-owned /bin to run `busybox --install` itself. Real
# images ship a populated /bin.
for app in $("$BB" --list 2>/dev/null); do
	[ "$app" = busybox ] && continue   # never clobber the real binary
	ln -sf busybox "$ROOT/bundle/rootfs/bin/$app"
done

# deterministic cgroup pids probe (calls fork(2) directly; see krunc-forktest)
FORKTEST="$REPO/userspace/target/x86_64-unknown-linux-musl/release/forktest"
if [ -x "$FORKTEST" ]; then
	cp "$FORKTEST" "$ROOT/bundle/rootfs/bin/forktest"
	chmod +x "$ROOT/bundle/rootfs/bin/forktest"
fi

# deterministic cgroup memory.max probe (allocates until OOM-killed; see krunc-memhog)
MEMHOG="$REPO/userspace/target/x86_64-unknown-linux-musl/release/memhog"
if [ -x "$MEMHOG" ]; then
	cp "$MEMHOG" "$ROOT/bundle/rootfs/bin/memhog"
	chmod +x "$ROOT/bundle/rootfs/bin/memhog"
fi

# device nodes (need root)
sudo mknod -m 600 "$ROOT/dev/console" c 5 1
sudo mknod -m 666 "$ROOT/dev/null"    c 1 3

# minimal /dev for the container rootfs so ordinary workloads (e.g. shells that
# redirect background jobs from /dev/null) behave; a hardened deployment would
# have the runtime build this from a tmpfs rather than shipping it in the image.
sudo mknod -m 666 "$ROOT/bundle/rootfs/dev/null" c 1 3
sudo mknod -m 666 "$ROOT/bundle/rootfs/dev/zero" c 1 5

# pack (root, to preserve nodes/ownership)
( cd "$ROOT" && sudo find . | sudo cpio -o -H newc --quiet ) | gzip -9 > "$OUT"
echo "==> initramfs: $OUT ($(du -h "$OUT" | cut -f1))"
