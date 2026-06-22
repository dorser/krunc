#!/usr/bin/env bash
# run-containerd.sh - boot a QEMU guest where the *real* containerd + nerdctl
# drive krunc as their OCI runtime, so you can `nerdctl run` / `ctr run`
# containers that the krunc kernel domain creates and enforces.
#
# Run scripts/setup-containerd-image.sh once first (it stages the containerd /
# nerdctl binaries and a busybox image under $STAGE). Quit the VM with
# `poweroff -f`.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
KDIR="${KDIR:-$HOME/linux-6.18}"
STAGE="${STAGE:-$HOME/stage}"
INITRAMFS="${INITRAMFS:-$HOME/krunc-containerd-initramfs.cpio.gz}"
BZ="$KDIR/arch/x86/boot/bzImage"

if [ ! -x "$STAGE/croot/bin/containerd" ]; then
	echo "==> staging containerd/nerdctl/busybox (first run)"
	bash "$REPO/scripts/setup-containerd-image.sh"
fi

[ -f "$REPO/module/krunc.ko" ] || bash "$REPO/scripts/build-module.sh"
[ -x "$REPO/userspace/target/x86_64-unknown-linux-musl/release/krunc" ] || bash "$REPO/scripts/build-cli.sh"

echo "==> building containerd initramfs"
INIT="$REPO/scripts/qemu-containerd-init.sh" OUT="$INITRAMFS" \
	IMAGES="$STAGE/images" EXTRA_DIR="$STAGE/croot" \
	bash "$REPO/scripts/make-initramfs.sh"

# Prefer hardware acceleration; self-heal /dev/kvm perms, else fall back to TCG.
KVM=()
if [ -e /dev/kvm ]; then
	[ -w /dev/kvm ] || sudo -n chmod 666 /dev/kvm 2>/dev/null || true
	if [ -w /dev/kvm ]; then
		KVM=(-enable-kvm -cpu host)
	else
		echo "==> /dev/kvm not writable; booting under TCG emulation (slower)." >&2
	fi
fi

echo "==> booting QEMU (containerd + krunc). Type 'poweroff -f' to quit."
exec qemu-system-x86_64 \
	"${KVM[@]}" \
	-smp 4 -m 4096 \
	-kernel "$BZ" \
	-initrd "$INITRAMFS" \
	-append "console=ttyS0 rdinit=/init loglevel=4" \
	-nographic -no-reboot
