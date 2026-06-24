#!/usr/bin/env bash
# build-bpf.sh - build krunc's BPF-LSM kill-on-escape program + loader.
#
# Produces (in module/ alongside the .ko's, so make-initramfs can stage them):
#   krunc_lsm.bpf.o      - the BPF_PROG_TYPE_LSM object (CO-RE, clang -target bpf)
#   krunc_lsm_loader     - a static loader that attaches it + guards a cgroup
#
# Requires a kernel built with CONFIG_DEBUG_INFO_BTF (for vmlinux.h) and the
# libbpf sources in the kernel tree (tools/lib/bpf). No kernel source patch.
set -euo pipefail
KDIR="${KDIR:-$HOME/linux-6.18}"
REPO="${REPO:-$HOME/krunc}"
OUT="$REPO/module"
BPF="$REPO/bpf"
VMLINUX="$KDIR/vmlinux"

command -v clang >/dev/null || { echo "clang required"; exit 1; }
[ -f "$VMLINUX" ] || { echo "missing $VMLINUX (build the kernel first)"; exit 1; }

echo "==> build bpftool + libbpf from the kernel tree"
make -C "$KDIR/tools/bpf/bpftool" >/dev/null
BPFTOOL="$KDIR/tools/bpf/bpftool/bpftool"
# libbpf static lib + headers produced by the bpftool build:
LIBBPF_A="$KDIR/tools/bpf/bpftool/libbpf/libbpf.a"
LIBBPF_INC="$KDIR/tools/bpf/bpftool/libbpf/include"

echo "==> generate vmlinux.h from kernel BTF"
"$BPFTOOL" btf dump file "$VMLINUX" format c > "$BPF/vmlinux.h"

echo "==> compile the BPF-LSM object (clang -target bpf, CO-RE)"
clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
	-I"$BPF" -I"$LIBBPF_INC" \
	-c "$BPF/krunc_lsm.bpf.c" -o "$OUT/krunc_lsm.bpf.o"

echo "==> compile the static loader"
clang -O2 -static \
	-I"$LIBBPF_INC" \
	"$BPF/krunc_lsm_loader.c" "$LIBBPF_A" \
	-lelf -lz -lzstd \
	-o "$OUT/krunc_lsm_loader"

echo "==> built:"
ls -l "$OUT/krunc_lsm.bpf.o" "$OUT/krunc_lsm_loader"
file "$OUT/krunc_lsm_loader" | sed 's/^/    /'
