#!/usr/bin/env bash
# build-kernel.sh - configure + build a VANILLA linux-6.18 with Rust support and
# a KVM-guest-friendly config for QEMU testing. No source patch is applied:
# krunc_helper.ko resolves the non-exported kernel primitives at load time via
# kprobe→kallsyms_lookup_name (needs CONFIG_KPROBES + CONFIG_KALLSYMS).
set -euo pipefail

KSRC="${KSRC:-$HOME/linux-6.18}"
REPO="${REPO:-$HOME/krunc}"
JOBS="${JOBS:-$(nproc)}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env"
export LLVM=1            # build the whole kernel (and Rust) with clang/lld

cd "$KSRC"

echo "==> base config: defconfig + kvm_guest.config"
make -j"$JOBS" defconfig
make -j"$JOBS" kvm_guest.config

echo "==> enable Rust, namespaces, modules, initramfs"
# CONFIG_RUST requires rustc >= 1.81 when CALL_PADDING is on (selected by the
# call-depth-tracking mitigation). We pin rustc 1.78 (the kernel's documented
# minimum), so disable that mitigation instead. Irrelevant for a PoC.
#
# KPROBES + KALLSYMS(_ALL) let krunc_helper.ko resolve the non-exported kernel
# primitives at load time (kprobe→kallsyms_lookup_name) — this is what makes
# krunc work on a VANILLA CONFIG_RUST kernel with NO source patch. KALLSYMS_ALL
# is required because one resolved symbol (uts_sem) is a data object, which plain
# KALLSYMS omits from the symbol table.
scripts/config \
	--enable RUST \
	--disable MODVERSIONS \
	--disable MITIGATION_CALL_DEPTH_TRACKING --disable CALL_THUNKS \
	--disable MODULE_SIG_FORCE \
	--enable MODULES --enable MODULE_UNLOAD \
	--enable KPROBES --enable KALLSYMS --enable KALLSYMS_ALL \
	--enable NAMESPACES \
	--enable PID_NS --enable UTS_NS --enable IPC_NS --enable NET_NS --enable USER_NS \
	--enable CGROUPS --enable CGROUP_PIDS --enable MEMCG \
	--enable DEVTMPFS --enable DEVTMPFS_MOUNT \
	--enable BLK_DEV_INITRD --enable RD_GZIP --enable RD_XZ \
	--enable TMPFS --enable PROC_FS --enable SYSFS --enable OVERLAY_FS \
	--enable SERIAL_8250 --enable SERIAL_8250_CONSOLE \
	--enable SAMPLES --enable SAMPLE_RUST --module SAMPLE_RUST_MISC_DEVICE

make -j"$JOBS" olddefconfig

echo "==> sanity: CONFIG_RUST must be y"
if ! grep -q '^CONFIG_RUST=y' .config; then
	echo "ERROR: CONFIG_RUST not enabled after olddefconfig" >&2
	grep -E 'CONFIG_RUST|CONFIG_HAVE_RUST' .config || true
	exit 1
fi
grep -E '^CONFIG_(RUST|PID_NS|NET_NS|UTS_NS|IPC_NS|MODULES|DEVTMPFS)=' .config

echo "==> building bzImage + modules with -j$JOBS (this is the long part)"
time make -j"$JOBS" bzImage modules

echo "==> done. bzImage at: $KSRC/arch/x86/boot/bzImage"
ls -l "$KSRC/arch/x86/boot/bzImage"
