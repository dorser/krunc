#!/usr/bin/env bash
# build-cli.sh - build the all-Rust krunc OCI CLI as a static (musl) binary so it
# runs in the busybox-only QEMU initramfs.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true
cd "$REPO/userspace"
rustup target add x86_64-unknown-linux-musl >/dev/null 2>&1 || true
cargo build --release --target x86_64-unknown-linux-musl -p krunc-cli -p krunc-forktest
BIN="target/x86_64-unknown-linux-musl/release/krunc"
echo "==> built: $BIN"
ls -l "$BIN"
file "$BIN" 2>/dev/null || true
FORKTEST="target/x86_64-unknown-linux-musl/release/forktest"
echo "==> built: $FORKTEST"
ls -l "$FORKTEST"
