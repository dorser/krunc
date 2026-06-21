#!/usr/bin/env bash
# run-test.sh - rebuild the module + initramfs and run the QEMU demo. Fast inner
# loop once the kernel has been built once with scripts/build-kernel.sh.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/.." && pwd)"
bash "$HERE/build-module.sh"
bash "$HERE/build-cli.sh"
# go-runc conformance tool (best-effort; needs network for the first build)
( cd "$REPO/conformance" && go mod tidy >/dev/null 2>&1 && CGO_ENABLED=0 go build -o krunc-conformance . ) || \
	echo "warning: krunc-conformance not built (containerd go-runc demo will be skipped)"
bash "$HERE/make-initramfs.sh"
echo "==> booting QEMU (Ctrl-A X to abort)"
bash "$HERE/run-qemu.sh"
