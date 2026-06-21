#!/usr/bin/env bash
# build-cli.sh - build the static krunc OCI CLI (pure Go stdlib, no cgo).
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
cd "$REPO/cli"
CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o krunc .
echo "==> built:"; ls -l krunc
./krunc --version
