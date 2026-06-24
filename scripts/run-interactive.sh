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

{ [ -f "$REPO/module/krunc.ko" ] && [ -f "$REPO/module/krunc_helper.ko" ]; } || bash "$REPO/scripts/build-module.sh"
[ -x "$REPO/userspace/target/x86_64-unknown-linux-musl/release/krunc" ] || bash "$REPO/scripts/build-cli.sh"

echo "==> building interactive initramfs"
INIT="$REPO/scripts/qemu-shell-init.sh" OUT="$INITRAMFS" bash "$REPO/scripts/make-initramfs.sh"

# Prefer hardware acceleration (KVM). If the device exists but isn't writable,
# try a one-shot, best-effort permission fix; otherwise fall back to TCG.
KVM=()
if [ -e /dev/kvm ]; then
	if [ ! -w /dev/kvm ]; then
		sudo -n chmod 666 /dev/kvm 2>/dev/null || true
	fi
	if [ -w /dev/kvm ]; then
		KVM=(-enable-kvm -cpu host)
	else
		echo "==> /dev/kvm not writable; booting under TCG emulation (slower)." >&2
	fi
else
	echo "==> no /dev/kvm; booting under TCG emulation (slower)." >&2
fi

echo "==> booting QEMU (interactive). Type 'poweroff -f' to quit."
exec qemu-system-x86_64 \
	"${KVM[@]}" \
	-smp 4 -m 2048 \
	-kernel "$BZ" \
	-initrd "$INITRAMFS" \
	-append "console=ttyS0 rdinit=/init loglevel=4" \
	-nographic -no-reboot
