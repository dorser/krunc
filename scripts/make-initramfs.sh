#!/usr/bin/env bash
# make-initramfs.sh - assemble a minimal initramfs containing busybox, the krunc
# module, the QEMU init, and an example container rootfs.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
OUT="${OUT:-$HOME/krunc-initramfs.cpio.gz}"
BB="$(command -v busybox || echo /bin/busybox)"
[ -x "$BB" ] || { echo "busybox-static not found (apt install busybox-static)"; exit 1; }
[ -f "$REPO/module/krunc.ko" ] || { echo "build krunc.ko first (scripts/build-module.sh)"; exit 1; }
[ -x "$REPO/cli/krunc" ] || { echo "build the CLI first (scripts/build-cli.sh)"; exit 1; }

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
         "$ROOT"/bundle/rootfs/sys "$ROOT"/bundle/rootfs/dev "$ROOT"/bundle/rootfs/tmp

# initramfs userland
cp "$BB" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
cp "$REPO/scripts/qemu-init.sh" "$ROOT/init"
cp "$REPO/module/krunc.ko" "$ROOT/krunc.ko"
cp "$REPO/cli/krunc" "$ROOT/bin/krunc"
chmod +x "$ROOT/init" "$ROOT/bin/busybox" "$ROOT/bin/krunc"
# go-runc conformance tool (uses containerd's runtime client library), optional
if [ -x "$REPO/conformance/krunc-conformance" ]; then
	cp "$REPO/conformance/krunc-conformance" "$ROOT/bin/krunc-conformance"
	chmod +x "$ROOT/bin/krunc-conformance"
fi

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

# device nodes (need root)
sudo mknod -m 600 "$ROOT/dev/console" c 5 1
sudo mknod -m 666 "$ROOT/dev/null"    c 1 3

# pack (root, to preserve nodes/ownership)
( cd "$ROOT" && sudo find . | sudo cpio -o -H newc --quiet ) | gzip -9 > "$OUT"
echo "==> initramfs: $OUT ($(du -h "$OUT" | cut -f1))"
