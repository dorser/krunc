#!/usr/bin/env bash
# run-bpflsm.sh - build + boot the M8 BPF-LSM escape-blocking demo under QEMU.
# Requires a kernel built with CONFIG_BPF_LSM + CONFIG_DEBUG_INFO_BTF (and "bpf"
# in CONFIG_LSM) -- see scripts/build-kernel.sh notes. No kernel source patch.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$HOME/krunc}"
INITRAMFS="${INITRAMFS:-$HOME/krunc-bpflsm-initramfs.cpio.gz}"

bash "$HERE/build-module.sh"
bash "$HERE/build-cli.sh"
bash "$HERE/build-bpf.sh"
INIT="$REPO/scripts/qemu-bpflsm-init.sh" OUT="$INITRAMFS" bash "$HERE/make-initramfs.sh"
echo "==> booting QEMU (BPF-LSM demo)"
INITRAMFS="$INITRAMFS" bash "$HERE/run-qemu.sh"
