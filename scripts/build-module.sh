#!/usr/bin/env bash
# build-module.sh - build the out-of-tree krunc Rust module against the kernel.
set -euo pipefail
KDIR="${KDIR:-$HOME/linux-6.18}"
REPO="${REPO:-$HOME/krunc}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env"

cd "$REPO/module"
make KDIR="$KDIR" clean >/dev/null 2>&1 || true
make KDIR="$KDIR"
echo "==> built:"
ls -l krunc.ko
modinfo krunc.ko | sed -n '1,12p'
