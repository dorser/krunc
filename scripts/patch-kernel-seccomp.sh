#!/usr/bin/env bash
# patch-kernel-seccomp.sh - idempotently append krunc's seccomp install helpers
# to the linux tree (net/core/filter.c + kernel/seccomp.c). These need the
# file-static BPF/seccomp helpers, so they cannot live in the standalone vmlinux
# shim (kernel-patch/krunc_exports.c); they are inserted in-place instead.
#
# The inserted region is delimited by KRUNC markers and is replaced (not merely
# skipped) on re-run, so editing the .inc files and re-running picks up changes.
set -euo pipefail
KSRC="${KSRC:-$HOME/linux-6.18}"
REPO="${REPO:-$HOME/krunc}"

# insert_block <file> <inc> <anchor-substring> <after|before>
insert_block() {
	python3 - "$1" "$2" "$3" "$4" <<'PY'
import sys
path, inc, anchor, where = sys.argv[1:5]
BEGIN = "/* ==== krunc seccomp patch (auto-inserted) ==== */\n"
END = "/* ==== end krunc seccomp patch ==== */\n"
src = open(path).read()
# Strip any previously inserted block so this is a true upsert.
b = src.find(BEGIN)
if b != -1:
    e = src.find(END, b)
    assert e != -1, "found BEGIN without END marker"
    src = src[:b] + src[e + len(END):]
block = BEGIN + open(inc).read().rstrip("\n") + "\n" + END
# Anchor on the whole line that contains the anchor substring.
line_start = src.index(anchor)
line_end = src.index("\n", line_start) + 1
pos = line_end if where == "after" else line_start
src = src[:pos] + "\n" + block + src[pos:]
open(path, "w").write(src)
PY
}

# append_block <file> <inc> : append the .inc at EOF (marker-delimited upsert).
append_block() {
	python3 - "$1" "$2" <<'PY'
import sys
path, inc = sys.argv[1:3]
BEGIN = "/* ==== krunc seccomp patch (auto-inserted) ==== */\n"
END = "/* ==== end krunc seccomp patch ==== */\n"
src = open(path).read()
b = src.find(BEGIN)
if b != -1:
    e = src.find(END, b)
    assert e != -1, "found BEGIN without END marker"
    src = src[:b] + src[e + len(END):]
block = BEGIN + open(inc).read().rstrip("\n") + "\n" + END
src = src.rstrip("\n") + "\n\n" + block
open(path, "w").write(src)
PY
}

insert_block "$KSRC/net/core/filter.c" "$REPO/kernel-patch/krunc_filter_add.inc" \
	"EXPORT_SYMBOL_GPL(bpf_prog_create_from_user);" after
echo "==> filter.c: krunc_bpf_prog_create_kern_trans installed"

# End of the CONFIG_SECCOMP_FILTER block holding the static seccomp helpers (the
# tab before the comment distinguishes it from the earlier space-prefixed one).
insert_block "$KSRC/kernel/seccomp.c" "$REPO/kernel-patch/krunc_seccomp_add.inc" \
	"$(printf '#endif\t/* CONFIG_SECCOMP_FILTER */')" before
echo "==> seccomp.c: krunc_seccomp_install installed"

# Landlock write-restrict helper: appended at EOF of the landlock syscalls TU,
# where the ruleset/cred helpers it needs are all visible. Only patched when the
# landlock source is present (CONFIG_SECURITY_LANDLOCK builds it).
if [ -f "$KSRC/security/landlock/syscalls.c" ]; then
	append_block "$KSRC/security/landlock/syscalls.c" "$REPO/kernel-patch/krunc_landlock_add.inc"
	echo "==> landlock/syscalls.c: krunc_landlock_restrict_writes installed"
fi
