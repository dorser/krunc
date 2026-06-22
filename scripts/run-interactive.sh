#!/usr/bin/env bash
# run-interactive.sh - build an initramfs whose /init drops you to a shell (with
# the krunc module loaded and /dev/krunc ready), then boot it under QEMU with the
# serial console wired to your terminal so you can drive krunc by hand.
#
# Quit the VM from inside with `poweroff -f`.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
KDIR="${KDIR:-$HOME/linux-6.18}"
INITRAMFS="${INITRAMFS:-$HOME/krunc-shell-initramfs.cpio.gz}"
BZ="$KDIR/arch/x86/boot/bzImage"

[ -f "$REPO/module/krunc.ko" ] || bash "$REPO/scripts/build-module.sh"
[ -x "$REPO/userspace/target/x86_64-unknown-linux-musl/release/krunc" ] || bash "$REPO/scripts/build-cli.sh"

echo "==> building interactive initramfs"
INIT="$REPO/scripts/qemu-shell-init.sh" OUT="$INITRAMFS" bash "$REPO/scripts/make-initramfs.sh"

KVM=()
[ -w /dev/kvm ] && KVM=(-enable-kvm -cpu host)

echo "==> booting QEMU (interactive). Type 'poweroff -f' to quit."
exec qemu-system-x86_64 \
	"${KVM[@]}" \
	-smp 4 -m 2048 \
	-kernel "$BZ" \
	-initrd "$INITRAMFS" \
	-append "console=ttyS0 rdinit=/init loglevel=4" \
	-nographic -no-reboot
