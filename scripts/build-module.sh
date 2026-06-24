#!/usr/bin/env bash
# build-module.sh - build the out-of-tree krunc modules against the kernel.
# Builds BOTH krunc_helper.ko (C kallsyms shim) and krunc.ko (Rust) in one
# pass; sharing the build dir's Module.symvers lets krunc.ko link against the
# helper's krunc_* exports with no KBUILD_EXTRA_SYMBOLS plumbing.
set -euo pipefail
KDIR="${KDIR:-$HOME/linux-6.18}"
REPO="${REPO:-$HOME/krunc}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env"

cd "$REPO/module"
make KDIR="$KDIR" clean >/dev/null 2>&1 || true
make KDIR="$KDIR"
echo "==> built:"
ls -l krunc_helper.ko krunc.ko
modinfo krunc_helper.ko | sed -n '1,6p'
modinfo krunc.ko | sed -n '1,12p'
