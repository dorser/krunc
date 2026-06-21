#!/usr/bin/env bash
# run-test.sh - rebuild the module + initramfs and run the QEMU demo. Fast inner
# loop once the kernel has been built once with scripts/build-kernel.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
bash "$HERE/build-module.sh"
bash "$HERE/build-cli.sh"
bash "$HERE/make-initramfs.sh"
echo "==> booting QEMU (Ctrl-A X to abort)"
bash "$HERE/run-qemu.sh"
