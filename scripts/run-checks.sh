#!/usr/bin/env bash
# run-checks.sh - build krunc and boot its QEMU demos, asserting the expected
# outcomes. A one-command regression check for the test VM: it turns the manual
# demos into pass/fail assertions (container isolation + confinement, read-only
# rootfs, sysctls, cgroup limits, clean unload, and — on a BPF-LSM kernel — the
# active kill-on-escape). Exit code 0 iff every check passed.
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${REPO:-$HOME/krunc}"
KDIR="${KDIR:-$HOME/linux-6.18}"
# shellcheck disable=SC1090
source "$HOME/.cargo/env" 2>/dev/null || true

fails=0
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fails=$((fails + 1)); }
# check <name> <log> <grep-args...>  (PASS if the pattern is present)
has()  { if grep -qE "$3" "$2"; then pass "$1"; else fail "$1"; fi; }
# absent <name> <log> <pattern>  (PASS if the pattern is ABSENT)
absent() { if grep -q "$3" "$2"; then fail "$1"; else pass "$1"; fi; }
# no real oops/panic. Detects only genuine kernel-fault markers — NOT a bare
# "Call Trace:", which also appears in the *expected* memcg OOM-kill dump (the
# demo deliberately OOM-kills memhog; that trace shows a userspace `RIP: 0033`).
# Ignores the boot cmdline `oops=panic` and the ACPI "report a bug" notice.
no_panic() {
	if grep -iE "kernel panic|Oops:|BUG:|general protection fault|unable to handle kernel" "$2" \
		| grep -ivE "oops=panic|report a bug" | grep -q .; then
		fail "$1"
	else
		pass "$1"
	fi
}

echo "==> building krunc (module + CLI)"
bash "$HERE/build-module.sh" >/tmp/checks-build.log 2>&1 || { echo "build-module FAILED"; tail -20 /tmp/checks-build.log; exit 1; }
bash "$HERE/build-cli.sh"    >>/tmp/checks-build.log 2>&1 || { echo "build-cli FAILED"; exit 1; }

BPF_LSM=0
if grep -q '^CONFIG_BPF_LSM=y' "$KDIR/.config" 2>/dev/null; then
	BPF_LSM=1
	bash "$HERE/build-bpf.sh" >>/tmp/checks-build.log 2>&1 || { echo "build-bpf FAILED"; tail -20 /tmp/checks-build.log; exit 1; }
fi

sudo -n chmod 666 /dev/kvm 2>/dev/null || true

echo "==> [1/2] lifecycle + confinement demo"
INIT="$REPO/scripts/qemu-init.sh" OUT="$HOME/krunc-checks-main.cpio.gz" bash "$HERE/make-initramfs.sh" >/dev/null 2>&1
INITRAMFS="$HOME/krunc-checks-main.cpio.gz" timeout 200 bash "$HERE/run-qemu.sh" >/tmp/checks-main.log 2>&1 || true
L=/tmp/checks-main.log
has    "container runs in fresh PID namespace (PID 1)" "$L" 'my pid .*: 1'
has    "namespaces isolated from host"                 "$L" 'pid: ISOLATED'
has    "OCI caps dropped (CapEff 0)"                   "$L" 'CapEff:[[:space:]]*0000000000000000'
has    "no_new_privs set"                              "$L" 'NoNewPrivs:[[:space:]]*1'
has    "runs as requested non-root user (65534)"       "$L" 'Uid:[[:space:]]*65534'
has    "read-only rootfs enforced (EROFS)"             "$L" 'rootfs / : read-only'
has    "writable /tmp scratch mount"                   "$L" '/tmp    : writable'
has    "sysctl applied (net.ipv4.ip_forward=1)"        "$L" 'net.ipv4.ip_forward = 1'
has    "pids cgroup enforced"                          "$L" 'pids cgroup ENFORCED'
has    "memory cgroup OOM-kill enforced"               "$L" 'memory cgroup ENFORCED'
has    "cpu cgroup throttling enforced"                "$L" 'cpu cgroup ENFORCED'
has    "malformed-spec decoder robust"                 "$L" 'kernel decoder is robust'
has    "module unloads cleanly"                        "$L" 'unloaded cleanly'
has    "all demos complete"                            "$L" 'all demos complete'
no_panic "no kernel panic/oops (lifecycle demo)"       "$L"

if [ "$BPF_LSM" = 1 ]; then
	echo "==> [2/2] BPF-LSM kill-on-escape demo"
	INIT="$REPO/scripts/qemu-bpflsm-init.sh" OUT="$HOME/krunc-checks-bpf.cpio.gz" bash "$HERE/make-initramfs.sh" >/dev/null 2>&1
	INITRAMFS="$HOME/krunc-checks-bpf.cpio.gz" timeout 200 bash "$HERE/run-qemu.sh" >/tmp/checks-bpf.log 2>&1 || true
	B=/tmp/checks-bpf.log
	has    "BPF-LSM hooks armed on the container cgroup" "$B" 'kill-on-escape hooks armed'
	absent "escape (userns create) blocked - marker absent" "$B" 'USERNS-CREATED-MARKER-FAIL'
	has    "escaping container terminated (stopped)"     "$B" '"status": "stopped"'
	no_panic "no kernel panic/oops (BPF-LSM demo)"       "$B"
else
	echo "==> [2/2] skipped: kernel has no CONFIG_BPF_LSM (build with KRUNC_BPF_LSM=1)"
fi

echo
if [ "$fails" = 0 ]; then
	echo "==> ALL CHECKS PASSED"
else
	echo "==> $fails CHECK(S) FAILED"
fi
exit "$fails"
