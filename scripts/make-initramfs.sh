#!/usr/bin/env bash
# make-initramfs.sh - assemble a minimal initramfs containing busybox, the krunc
# module, the QEMU init, and an example container rootfs.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
OUT="${OUT:-$HOME/krunc-initramfs.cpio.gz}"
BB="$(command -v busybox || echo /bin/busybox)"
[ -x "$BB" ] || { echo "busybox-static not found (apt install busybox-static)"; exit 1; }
[ -f "$REPO/module/krunc.ko" ] || { echo "build krunc.ko first (scripts/build-module.sh)"; exit 1; }

ROOT="$(mktemp -d)"
cleanup() { sudo rm -rf "$ROOT"; }
trap cleanup EXIT

# directory skeleton
mkdir -p "$ROOT"/bin "$ROOT"/sbin "$ROOT"/proc "$ROOT"/sys "$ROOT"/dev "$ROOT"/tmp
mkdir -p "$ROOT"/containers/demo/bin "$ROOT"/containers/demo/proc \
         "$ROOT"/containers/demo/sys "$ROOT"/containers/demo/dev \
         "$ROOT"/containers/demo/tmp

# initramfs userland
cp "$BB" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
cp "$REPO/scripts/qemu-init.sh" "$ROOT/init"
cp "$REPO/module/krunc.ko" "$ROOT/krunc.ko"
chmod +x "$ROOT/init" "$ROOT/bin/busybox"

# example container rootfs
cp "$BB" "$ROOT/containers/demo/bin/busybox"
ln -sf busybox "$ROOT/containers/demo/bin/sh"
cp "$REPO/examples/rootfs-skel/init.sh" "$ROOT/containers/demo/init.sh"
chmod +x "$ROOT/containers/demo/init.sh" "$ROOT/containers/demo/bin/busybox"

# device nodes (need root)
sudo mknod -m 600 "$ROOT/dev/console" c 5 1
sudo mknod -m 666 "$ROOT/dev/null"    c 1 3

# pack (root, to preserve nodes/ownership)
( cd "$ROOT" && sudo find . | sudo cpio -o -H newc --quiet ) | gzip -9 > "$OUT"
echo "==> initramfs: $OUT ($(du -h "$OUT" | cut -f1))"
