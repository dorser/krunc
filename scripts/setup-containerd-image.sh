#!/usr/bin/env bash
# setup-containerd-image.sh - stage the artifacts needed to drive krunc from a
# real higher-level runtime inside QEMU: the containerd + nerdctl + runc-v2 shim
# binaries, and a busybox OCI image (fetched without a daemon via crane) plus an
# extracted busybox rootfs. Idempotent; safe to re-run. Writes under $STAGE.
set -euo pipefail
STAGE="${STAGE:-$HOME/stage}"
mkdir -p "$STAGE"
cd "$STAGE"

ARCH=amd64
need() { command -v "$1" >/dev/null 2>&1; }

# --- containerd + nerdctl + runc, from the nerdctl-full release bundle ---
if [ ! -x "$STAGE/croot/bin/containerd" ]; then
	NV="$(curl -fsSL https://api.github.com/repos/containerd/nerdctl/releases/latest \
		| grep -oP '"tag_name": "v\K[^"]+' | head -1)"
	echo "==> downloading nerdctl-full v$NV"
	curl -fsSL -o nerdctl-full.tgz \
		"https://github.com/containerd/nerdctl/releases/download/v${NV}/nerdctl-full-${NV}-linux-${ARCH}.tar.gz"
	rm -rf nerdctl-full && mkdir -p nerdctl-full
	tar -C nerdctl-full -xzf nerdctl-full.tgz
	mkdir -p croot/bin croot/images-archive croot/var/log
	cp nerdctl-full/bin/{containerd,containerd-shim-runc-v2,ctr,nerdctl,runc} croot/bin/
	chmod +x croot/bin/*
fi

# --- crane: pull an OCI image to a tarball without a container daemon ---
if [ ! -x "$STAGE/crane" ]; then
	CV="$(curl -fsSL https://api.github.com/repos/google/go-containerregistry/releases/latest \
		| grep -oP '"tag_name": "v\K[^"]+' | head -1)"
	echo "==> downloading crane v$CV"
	curl -fsSL -o crane.tgz \
		"https://github.com/google/go-containerregistry/releases/download/v${CV}/go-containerregistry_Linux_x86_64.tar.gz"
	tar xzf crane.tgz crane
fi

# --- busybox: an OCI image archive (for containerd) + an extracted rootfs ---
if [ ! -f "$STAGE/croot/images-archive/busybox-oci.tar" ]; then
	echo "==> fetching busybox image"
	./crane pull busybox:latest croot/images-archive/busybox-oci.tar
fi
if [ ! -x "$STAGE/images/busybox/bin/busybox" ]; then
	echo "==> extracting busybox rootfs (for 'krunc run --image busybox')"
	mkdir -p images/busybox
	./crane export busybox:latest - | tar -C images/busybox -xf -
	# minimal device nodes so simple workloads behave without a /dev mount
	sudo mkdir -p images/busybox/dev
	sudo sh -c 'cd images/busybox/dev
		mknod -m 666 null c 1 3; mknod -m 666 zero c 1 5; mknod -m 666 full c 1 7
		mknod -m 666 random c 1 8; mknod -m 666 urandom c 1 9
		mknod -m 666 tty c 5 0; mknod -m 622 console c 5 1; true' 2>/dev/null || true
fi

echo "==> staged under $STAGE:"
echo "    croot/bin: $(ls "$STAGE"/croot/bin | tr '\n' ' ')"
echo "    image archive: $(ls "$STAGE"/croot/images-archive)"
echo "    rootfs image:  images/busybox"
