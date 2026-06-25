#!/usr/bin/env bash
# run-realimage.sh - end-to-end demo proving krunc runs a REAL OCI image.
#
# Downloads the official Alpine Linux minirootfs (an unmodified distribution
# image), extracts it, builds a QEMU initramfs with it staged at /alpine, boots
# it, and runs the real Alpine userland as a krunc container via `krunc run`.
# Asserts the genuine distro ran ("Alpine Linux") under full krunc confinement
# (CapEff=0, NoNewPrivs=1) and exited cleanly.
#
# Prereqs: the kernel + modules + CLI are already built on this machine (run
# scripts/build-kernel.sh once, then this script builds the module/CLI). Run on
# the krunc VM (nested KVM). Override ALPINE_VERSION / ALPINE_ARCH as needed.
set -euo pipefail
cd "$(dirname "$0")/.."
REPO="$PWD"

ALPINE_VERSION="${ALPINE_VERSION:-3.20.3}"
ALPINE_BRANCH="v${ALPINE_VERSION%.*}"
ALPINE_ARCH="${ALPINE_ARCH:-x86_64}"
TARBALL="alpine-minirootfs-${ALPINE_VERSION}-${ALPINE_ARCH}.tar.gz"
URL="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_BRANCH}/releases/${ALPINE_ARCH}/${TARBALL}"
ROOTFS="${ALPINE_ROOTFS:-$HOME/alpine-rootfs}"
LOG="${LOG:-/tmp/krunc-realimage.log}"

if [ ! -e "$ROOTFS/etc/alpine-release" ]; then
	echo "==> fetching real OCI image: $URL"
	tmp="$(mktemp)"
	curl -fsSL --max-time 60 -o "$tmp" "$URL"
	rm -rf "$ROOTFS"; mkdir -p "$ROOTFS"
	sudo tar -xzf "$tmp" -C "$ROOTFS"
	rm -f "$tmp"
fi
echo "==> Alpine rootfs: $ROOTFS ($(cat "$ROOTFS/etc/alpine-release"))"

echo "==> building krunc module + CLI"
LLVM=1 bash scripts/build-module.sh >/tmp/krunc-bm.log 2>&1
bash scripts/build-cli.sh >/tmp/krunc-bc.log 2>&1

echo "==> building initramfs with the real image staged at /alpine"
ALPINE_ROOTFS="$ROOTFS" INIT="$REPO/scripts/qemu-realimage-init.sh" \
	OUT="$HOME/krunc-realimage.cpio.gz" bash scripts/make-initramfs.sh >/dev/null

echo "==> booting QEMU and running the real image under krunc"
sudo chmod 666 /dev/kvm 2>/dev/null || true
INITRAMFS="$HOME/krunc-realimage.cpio.gz" timeout 180 bash scripts/run-qemu.sh >"$LOG" 2>&1 || true

echo "==> result"
sed -n '/krunc - run a REAL OCI image/,/demo complete/p' "$LOG" | sed 's/^/  /'

fail=0
grep -q 'NAME="Alpine Linux"'      "$LOG" || { echo "FAIL: Alpine image did not run"; fail=1; }
grep -q 'ALPINE-RAN-OK'            "$LOG" || { echo "FAIL: entrypoint did not complete"; fail=1; }
grep -q 'CapEff=0000000000000000' "$LOG" || { echo "FAIL: capabilities not dropped"; fail=1; }
grep -q 'NoNewPrivs=1'            "$LOG" || { echo "FAIL: no_new_privs not set"; fail=1; }
grep -q 'krunc run exit code: 0'  "$LOG" || { echo "FAIL: non-zero exit"; fail=1; }
if grep -iE "kernel panic|Oops:|BUG:|general protection fault|unable to handle kernel" "$LOG" \
	| grep -ivE "oops=panic|report a bug" | grep -q .; then
	echo "FAIL: kernel panic/oops"; fail=1
fi

if [ "$fail" -eq 0 ]; then
	echo "==> PASS: krunc ran a real Alpine Linux image end-to-end, fully confined."
else
	echo "==> FAILURES above; full log: $LOG"; exit 1
fi
