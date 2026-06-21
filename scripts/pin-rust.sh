#!/usr/bin/env bash
# pin-rust.sh <kernel-src-dir> - install the exact rustc/bindgen the kernel requires.
set -euo pipefail
KSRC="${1:?usage: pin-rust.sh <kernel-src-dir>}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env"

RUSTC_VER="$(cd "$KSRC" && scripts/min-tool-version.sh rustc)"
BINDGEN_VER="$(cd "$KSRC" && scripts/min-tool-version.sh bindgen)"
echo "==> kernel wants rustc=$RUSTC_VER bindgen=$BINDGEN_VER"

rustup toolchain install "$RUSTC_VER" --profile minimal --component rust-src
rustup default "$RUSTC_VER"

if ! command -v bindgen >/dev/null 2>&1 || [ "$(bindgen --version 2>/dev/null | awk '{print $2}')" != "$BINDGEN_VER" ]; then
	echo "==> installing bindgen-cli $BINDGEN_VER"
	cargo install --locked --version "$BINDGEN_VER" bindgen-cli
fi

echo "==> versions"
rustc --version
bindgen --version
echo "==> rust-src present:"; rustc --print sysroot
ls "$(rustc --print sysroot)/lib/rustlib/src/rust/library/core" >/dev/null && echo "rust-src OK"
