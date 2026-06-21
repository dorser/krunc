#!/usr/bin/env bash
# vm-setup.sh - install kernel + Rust-for-Linux build dependencies on the test VM.
# Idempotent-ish; safe to re-run. Run as a sudo-capable user.
set -euo pipefail

echo "==> apt deps"
export DEBIAN_FRONTEND=noninteractive
sudo apt-get update -y
sudo apt-get install -y --no-install-recommends \
	build-essential bc bison flex \
	libssl-dev libelf-dev libncurses-dev \
	dwarves cpio kmod rsync git curl ca-certificates \
	clang lld llvm libclang-dev \
	qemu-system-x86 qemu-utils \
	busybox-static \
	pkg-config

echo "==> rustup"
if ! command -v rustup >/dev/null 2>&1; then
	curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
		| sh -s -- -y --default-toolchain none --profile minimal
fi
# shellcheck disable=SC1090
source "$HOME/.cargo/env"

echo "==> done base toolchain"
rustup --version || true
clang --version | head -1 || true
echo "Next: run pin-rust.sh <kernel-src-dir> to install the exact rustc/bindgen the kernel wants."
