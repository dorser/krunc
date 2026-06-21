#!/usr/bin/env bash
# build-kernel.sh - configure + build linux-6.18 with Rust support, the krunc
# vmlinux export shim, and a KVM-guest-friendly config for QEMU testing.
set -euo pipefail

KSRC="${KSRC:-$HOME/linux-6.18}"
REPO="${REPO:-$HOME/krunc}"
JOBS="${JOBS:-$(nproc)}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env"
export LLVM=1            # build the whole kernel (and Rust) with clang/lld

cd "$KSRC"

echo "==> install vmlinux export shim (krunc_exports.c)"
cp "$REPO/kernel-patch/krunc_exports.c" kernel/krunc_exports.c
if ! grep -q 'krunc_exports.o' kernel/Makefile; then
	echo 'obj-y += krunc_exports.o' >> kernel/Makefile
fi

echo "==> apply in-tree seccomp install helpers (filter.c + seccomp.c)"
bash "$REPO/scripts/patch-kernel-seccomp.sh"

echo "==> base config: defconfig + kvm_guest.config"
make -j"$JOBS" defconfig
make -j"$JOBS" kvm_guest.config

echo "==> enable Rust, namespaces, modules, initramfs"
# CONFIG_RUST requires rustc >= 1.81 when CALL_PADDING is on (selected by the
# call-depth-tracking mitigation). We pin rustc 1.78 (the kernel's documented
# minimum), so disable that mitigation instead. Irrelevant for a PoC.
scripts/config \
	--enable RUST \
	--disable MODVERSIONS \
	--disable MITIGATION_CALL_DEPTH_TRACKING --disable CALL_THUNKS \
	--disable MODULE_SIG_FORCE \
	--enable MODULES --enable MODULE_UNLOAD \
	--enable NAMESPACES \
	--enable PID_NS --enable UTS_NS --enable IPC_NS --enable NET_NS --enable USER_NS \
	--enable SECCOMP --enable SECCOMP_FILTER \
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
