#!/usr/bin/env bash
# run-qemu.sh - boot the krunc test kernel + initramfs under QEMU/KVM and stream
# the serial console. The initramfs /init runs the demo and powers off.
set -euo pipefail
KDIR="${KDIR:-$HOME/linux-6.18}"
INITRAMFS="${INITRAMFS:-$HOME/krunc-initramfs.cpio.gz}"
BZ="$KDIR/arch/x86/boot/bzImage"
TIMEOUT="${TIMEOUT:-120}"
[ -f "$BZ" ] || { echo "missing bzImage: $BZ"; exit 1; }
[ -f "$INITRAMFS" ] || { echo "missing initramfs: $INITRAMFS"; exit 1; }

KVM=()
[ -w /dev/kvm ] && KVM=(-enable-kvm -cpu host)

exec timeout "$TIMEOUT" qemu-system-x86_64 \
	"${KVM[@]}" \
	-smp 4 -m 2048 \
	-kernel "$BZ" \
	-initrd "$INITRAMFS" \
	-append "console=ttyS0 rdinit=/init loglevel=7 oops=panic panic=-1" \
	-nographic -no-reboot
