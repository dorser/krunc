#!/usr/bin/env bash
# make-initramfs.sh - assemble a minimal initramfs containing busybox, the krunc
# module, the QEMU init, and an example container rootfs.
set -euo pipefail
REPO="${REPO:-$HOME/krunc}"
OUT="${OUT:-$HOME/krunc-initramfs.cpio.gz}"
BB="$(command -v busybox || echo /bin/busybox)"
[ -x "$BB" ] || { echo "busybox-static not found (apt install busybox-static)"; exit 1; }
[ -f "$REPO/module/krunc.ko" ] || { echo "build krunc.ko first (scripts/build-module.sh)"; exit 1; }
[ -f "$REPO/module/krunc_helper.ko" ] || { echo "build krunc_helper.ko first (scripts/build-module.sh)"; exit 1; }
KRUNC_BIN="$REPO/userspace/target/x86_64-unknown-linux-musl/release/krunc"
[ -x "$KRUNC_BIN" ] || { echo "build the CLI first (scripts/build-cli.sh)"; exit 1; }

ROOT="$(mktemp -d)"
cleanup() { sudo rm -rf "$ROOT"; }
trap cleanup EXIT

# directory skeleton
mkdir -p "$ROOT"/bin "$ROOT"/sbin "$ROOT"/proc "$ROOT"/sys "$ROOT"/dev "$ROOT"/tmp "$ROOT"/run
mkdir -p "$ROOT"/containers/demo/bin "$ROOT"/containers/demo/proc \
         "$ROOT"/containers/demo/sys "$ROOT"/containers/demo/dev \
         "$ROOT"/containers/demo/tmp
# OCI bundle (config.json + rootfs) for the runc-compatible CLI demo
mkdir -p "$ROOT"/bundle/rootfs/bin "$ROOT"/bundle/rootfs/proc \
         "$ROOT"/bundle/rootfs/sys "$ROOT"/bundle/rootfs/dev "$ROOT"/bundle/rootfs/tmp \
         "$ROOT"/bundle/rootfs/etc

# initramfs userland
cp "$BB" "$ROOT/bin/busybox"
ln -sf busybox "$ROOT/bin/sh"
cp "${INIT:-$REPO/scripts/qemu-init.sh}" "$ROOT/init"
cp "$REPO/module/krunc_helper.ko" "$ROOT/krunc_helper.ko"
cp "$REPO/module/krunc.ko" "$ROOT/krunc.ko"
cp "$KRUNC_BIN" "$ROOT/bin/krunc"
chmod +x "$ROOT/init" "$ROOT/bin/busybox" "$ROOT/bin/krunc"

# All-Rust (aya) BPF-LSM loader, if built (scripts/build-cli.sh). The CLI invokes
# it across the container lifecycle to arm/tear down per-container LSM guarding.
KRUNC_BPF="$REPO/userspace/target/x86_64-unknown-linux-musl/release/krunc-bpf"
if [ -x "$KRUNC_BPF" ]; then
	cp "$KRUNC_BPF" "$ROOT/bin/krunc-bpf"
	chmod +x "$ROOT/bin/krunc-bpf"
fi

# example container rootfs (text interface)
cp "$BB" "$ROOT/containers/demo/bin/busybox"
ln -sf busybox "$ROOT/containers/demo/bin/sh"
cp "$REPO/examples/rootfs-skel/init.sh" "$ROOT/containers/demo/init.sh"
chmod +x "$ROOT/containers/demo/init.sh" "$ROOT/containers/demo/bin/busybox"

# OCI bundle rootfs (same busybox app) + config.json
cp "$BB" "$ROOT/bundle/rootfs/bin/busybox"
ln -sf busybox "$ROOT/bundle/rootfs/bin/sh"
cp "$REPO/examples/rootfs-skel/init.sh" "$ROOT/bundle/rootfs/init.sh"
cp "$REPO/examples/bundle/config.json" "$ROOT/bundle/config.json"
chmod +x "$ROOT/bundle/rootfs/init.sh" "$ROOT/bundle/rootfs/bin/busybox"

# Pre-install the busybox applet symlinks at build time so the bundle works when
# the container runs as a non-root user (config.json sets process.user), which
# cannot write the root-owned /bin to run `busybox --install` itself. Real
# images ship a populated /bin.
for app in $("$BB" --list 2>/dev/null); do
	[ "$app" = busybox ] && continue   # never clobber the real binary
	ln -sf busybox "$ROOT/bundle/rootfs/bin/$app"
done

# deterministic cgroup pids probe (calls fork(2) directly; see krunc-forktest)
FORKTEST="$REPO/userspace/target/x86_64-unknown-linux-musl/release/forktest"
if [ -x "$FORKTEST" ]; then
	cp "$FORKTEST" "$ROOT/bundle/rootfs/bin/forktest"
	chmod +x "$ROOT/bundle/rootfs/bin/forktest"
fi

# deterministic cgroup memory.max probe (allocates until OOM-killed; see krunc-memhog)
MEMHOG="$REPO/userspace/target/x86_64-unknown-linux-musl/release/memhog"
if [ -x "$MEMHOG" ]; then
	cp "$MEMHOG" "$ROOT/bundle/rootfs/bin/memhog"
	chmod +x "$ROOT/bundle/rootfs/bin/memhog"
fi

# deterministic cgroup cpu.max throttling probe (CPU-bound loop; see krunc-cpuhog)
CPUHOG="$REPO/userspace/target/x86_64-unknown-linux-musl/release/cpuhog"
if [ -x "$CPUHOG" ]; then
	cp "$CPUHOG" "$ROOT/bundle/rootfs/bin/cpuhog"
	chmod +x "$ROOT/bundle/rootfs/bin/cpuhog"
fi

# Minimal bundle whose entrypoint exits 42, to exercise exit-code reaping: krunc
# captures the init's wait-status (even as a lingering zombie) and `krunc state`
# reports `org.krunc.exitCode`. Shares the busybox rootfs; `exit` is a shell
# builtin so only /bin/sh is needed.
mkdir -p "$ROOT"/bundle-rc42/rootfs/bin "$ROOT"/bundle-rc42/rootfs/proc
cp "$BB" "$ROOT/bundle-rc42/rootfs/bin/busybox"
ln -sf busybox "$ROOT/bundle-rc42/rootfs/bin/sh"
chmod +x "$ROOT/bundle-rc42/rootfs/bin/busybox"
cat > "$ROOT/bundle-rc42/config.json" <<'CFG'
{
  "ociVersion": "1.0.2-dev",
  "hostname": "rc42",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", "exit 42"],
    "env": ["PATH=/bin"],
    "cwd": "/",
    "noNewPrivileges": true,
    "capabilities": { "bounding": [] }
  },
  "root": { "path": "rootfs", "readonly": false },
  "linux": {
    "namespaces": [
      { "type": "pid" }, { "type": "mount" }, { "type": "uts" }
    ]
  },
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" }
  ]
}
CFG

# Bundle exercising USER NAMESPACES + uid/gid mappings: container uid/gid 0 maps
# to host 100000 (an unprivileged host id). The entrypoint prints its in-container
# ids; the demo init then checks the HOST view of the same task to prove the
# kernel wrote /proc/<pid>/{uid,gid}_map (host sees uid 100000). Static busybox so
# rootfs files (host-root-owned, hence "nobody" in the unmapped portion) need no
# interpreter; busybox is mode 0755 so the mapped root can still exec it.
mkdir -p "$ROOT"/bundle-userns/rootfs/bin "$ROOT"/bundle-userns/rootfs/proc \
         "$ROOT"/bundle-userns/rootfs/tmp
cp "$BB" "$ROOT/bundle-userns/rootfs/bin/busybox"
ln -sf busybox "$ROOT/bundle-userns/rootfs/bin/sh"
chmod +x "$ROOT/bundle-userns/rootfs/bin/busybox"
for app in $("$BB" --list 2>/dev/null); do
	[ "$app" = busybox ] && continue
	ln -sf busybox "$ROOT/bundle-userns/rootfs/bin/$app"
done
# Own the rootfs by the MAPPED host range (container uid/gid 0 -> host 100000),
# as a real rootless runtime would (via chown or idmapped mounts). Otherwise the
# files are owned by host uid 0, which is unmapped inside the container's user
# namespace, so the container init cannot traverse/chroot into them.
sudo chown -R 100000:100000 "$ROOT/bundle-userns/rootfs"
cat > "$ROOT/bundle-userns/config.json" <<'CFG'
{
  "ociVersion": "1.0.2-dev",
  "hostname": "userns",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/sh", "-c", "echo userns-inside uid=$(id -u) gid=$(id -g); grep -E '^Uid|^Gid' /proc/self/status; echo USERNS-RAN-OK; sleep 3"],
    "env": ["PATH=/bin"],
    "cwd": "/",
    "noNewPrivileges": true,
    "capabilities": { "bounding": [] }
  },
  "root": { "path": "rootfs", "readonly": false },
  "linux": {
    "namespaces": [
      { "type": "user" }, { "type": "pid" }, { "type": "mount" }, { "type": "uts" }
    ],
    "uidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
    "gidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ]
  },
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" }
  ]
}
CFG

# (scripts/build-bpf.sh), stage the loadable LSM object + static loader and a
# minimal "escape" bundle whose PID 1 opens a tripwire file. The demo init
# (scripts/qemu-bpflsm-init.sh) guards the container's cgroup, so the open is
# denied and the container is SIGKILL'd by the BPF-LSM program.
if [ -f "$REPO/module/krunc_lsm.bpf.o" ] && [ -x "$REPO/module/krunc_lsm_loader" ]; then
	cp "$REPO/module/krunc_lsm.bpf.o" "$ROOT/krunc_lsm.bpf.o"
	cp "$REPO/module/krunc_lsm_loader" "$ROOT/bin/krunc_lsm_loader"
	chmod +x "$ROOT/bin/krunc_lsm_loader"
	mkdir -p "$ROOT"/esc/rootfs/bin "$ROOT"/esc/rootfs/proc \
	         "$ROOT"/esc/rootfs/sys "$ROOT"/esc/rootfs/dev "$ROOT"/esc/rootfs/tmp
	cp "$BB" "$ROOT/esc/rootfs/bin/busybox"
	ln -sf busybox "$ROOT/esc/rootfs/bin/sh"
	ln -sf busybox "$ROOT/esc/rootfs/bin/cat"
	ln -sf busybox "$ROOT/esc/rootfs/bin/echo"
	# the tripwire: if the BPF-LSM fails to deny+kill, cat prints this content.
	printf 'ESCAPE-SUCCEEDED-BPF-LSM-FAILED\n' > "$ROOT/esc/rootfs/krunc-escape"
	cp "$REPO/examples/bundle/esc-config.json" "$ROOT/esc/config.json"
	chmod +x "$ROOT/esc/rootfs/bin/busybox"

	# CLI-driven variant: same escape entrypoint, but BPF-LSM is armed by the
	# `krunc` CLI itself (org.krunc.bpf-lsm=block annotation) at create and torn
	# down at delete — no manual loader call. Used by scripts/qemu-aya-cli-init.sh.
	mkdir -p "$ROOT"/esc-cli
	cp -a "$ROOT/esc/rootfs" "$ROOT/esc-cli/rootfs"
	cp "$REPO/examples/bundle/esc-cli-config.json" "$ROOT/esc-cli/config.json"
fi

# Optional: OCI conformance bundle running the official opencontainers/
# runtime-tools `runtimetest` as the container entrypoint (see
# scripts/qemu-conformance-init.sh). The config stays within krunc's accepted
# subset; runtimetest (cwd "/") reads /config.json inside the container and
# compares it against the live state, so the same document is written to the
# bundle (for krunc) and into the rootfs (for runtimetest).
RUNTIMETEST="${RUNTIMETEST:-}"
if [ -n "$RUNTIMETEST" ] && [ -x "$RUNTIMETEST" ]; then
	mkdir -p "$ROOT"/conformance/rootfs/bin "$ROOT"/conformance/rootfs/proc \
	         "$ROOT"/conformance/rootfs/tmp
	cp "$BB" "$ROOT/conformance/rootfs/bin/busybox"
	ln -sf busybox "$ROOT/conformance/rootfs/bin/sh"
	cp "$RUNTIMETEST" "$ROOT/conformance/rootfs/bin/runtimetest"
	chmod +x "$ROOT/conformance/rootfs/bin/runtimetest"
	cat > "$ROOT/conformance/config.json" <<'CFG'
{
  "ociVersion": "1.0.2-dev",
  "hostname": "krunc-conformance",
  "process": {
    "terminal": false,
    "user": { "uid": 0, "gid": 0 },
    "args": ["/bin/runtimetest", "--path", "/"],
    "env": ["PATH=/bin", "TERM=linux", "HOME=/root"],
    "cwd": "/",
    "noNewPrivileges": true,
    "capabilities": {
      "bounding": ["CAP_KILL", "CAP_CHOWN", "CAP_NET_BIND_SERVICE"],
      "effective": ["CAP_KILL", "CAP_CHOWN", "CAP_NET_BIND_SERVICE"],
      "permitted": ["CAP_KILL", "CAP_CHOWN", "CAP_NET_BIND_SERVICE"]
    },
    "oomScoreAdj": -100,
    "rlimits": [
      { "type": "RLIMIT_NOFILE", "soft": 1024, "hard": 1024 }
    ]
  },
  "root": { "path": "rootfs", "readonly": false },
  "linux": {
    "namespaces": [
      { "type": "pid" }, { "type": "mount" }, { "type": "uts" },
      { "type": "ipc" }, { "type": "network" }
    ],
    "maskedPaths": ["/proc/kcore"],
    "readonlyPaths": ["/proc/sys"]
  },
  "mounts": [
    { "destination": "/proc", "type": "proc", "source": "proc" },
    { "destination": "/dev", "type": "tmpfs", "source": "tmpfs",
      "options": ["nosuid"] },
    { "destination": "/dev/pts", "type": "devpts", "source": "devpts",
      "options": ["nosuid", "noexec"] },
    { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
      "options": ["nosuid", "nodev"] }
  ]
}
CFG
	cp "$ROOT/conformance/config.json" "$ROOT/conformance/rootfs/config.json"
	echo "==> bundled OCI conformance runtimetest"
fi

# Optional: prebuilt docker-style images for `krunc run --image <name> <cmd>`.
# Each subdirectory of $IMAGES is an already-extracted rootfs (carrying its own
# /dev nodes); `cp -a` preserves those nodes and the cpio below runs as root.
IMAGES="${IMAGES:-$HOME/stage/images}"
if [ -d "$IMAGES" ]; then
	mkdir -p "$ROOT/images"
	sudo cp -a "$IMAGES"/. "$ROOT/images"/
	echo "==> bundled images: $(ls "$ROOT/images" | tr '\n' ' ')"
fi

# Optional: a real Alpine Linux rootfs (extracted alpine-minirootfs) staged at
# /alpine, to demonstrate krunc running a genuine distribution image end-to-end
# (see scripts/qemu-realimage-init.sh). `cp -a` preserves the device nodes and
# symlinks the official image ships; the cpio pack below runs as root.
ALPINE_ROOTFS="${ALPINE_ROOTFS:-}"
if [ -n "$ALPINE_ROOTFS" ] && [ -d "$ALPINE_ROOTFS" ]; then
	mkdir -p "$ROOT/alpine"
	sudo cp -a "$ALPINE_ROOTFS"/. "$ROOT/alpine"/
	echo "==> bundled real image: Alpine rootfs ($(du -sh "$ALPINE_ROOTFS" | cut -f1))"
fi

# Optional: extra files overlaid onto the initramfs root (e.g. containerd +
# nerdctl binaries and a runtime config for the real higher-level-runtime image).
EXTRA_DIR="${EXTRA_DIR:-}"
if [ -n "$EXTRA_DIR" ] && [ -d "$EXTRA_DIR" ]; then
	sudo cp -a "$EXTRA_DIR"/. "$ROOT"/
	echo "==> overlaid extra files from $EXTRA_DIR"
fi

# device nodes (need root)
sudo mknod -m 600 "$ROOT/dev/console" c 5 1
sudo mknod -m 666 "$ROOT/dev/null"    c 1 3

# minimal /dev for the container rootfs so ordinary workloads (e.g. shells that
# redirect background jobs from /dev/null) behave; a hardened deployment would
# have the runtime build this from a tmpfs rather than shipping it in the image.
sudo mknod -m 666 "$ROOT/bundle/rootfs/dev/null" c 1 3
sudo mknod -m 666 "$ROOT/bundle/rootfs/dev/zero" c 1 5

# pack (root, to preserve nodes/ownership)
# Ensure the initramfs root is world-traversable: mktemp -d makes it 0700, which
# would block a user-namespaced container's init (an unprivileged, *mapped* uid)
# from traversing "/" to reach its bundle/rootfs. Real bundle paths are 0755.
sudo chmod 755 "$ROOT"
( cd "$ROOT" && sudo find . | sudo cpio -o -H newc --quiet ) | gzip -9 > "$OUT"
echo "==> initramfs: $OUT ($(du -h "$OUT" | cut -f1))"
