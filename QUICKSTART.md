# krunc quickstart

Get krunc — a container runtime that lives **inside the kernel** as a Rust module
— built and running containers on a throwaway machine, end to end. By the end you
will have booted a vanilla `CONFIG_RUST` kernel under QEMU, loaded the two krunc
modules, and run an OCI container with the `krunc` CLI.

> **Why a VM + QEMU?** krunc is a kernel module, and a bug in it can panic the
> kernel. So you never load it on a machine you care about: you build a custom
> kernel and boot it **under QEMU/KVM**, where a panic just kills the guest. The
> kernel needs `CONFIG_RUST=y` (no stock distro ships it), which is why you build
> one — but there is **no kernel source patch**: krunc resolves the kernel
> primitives it needs at load time via a helper module (see
> [How it works](#how-it-works)).

There are two layers of machine here:

| Layer | What it is | Touched by krunc? |
|---|---|---|
| **Build host** | a Linux box where you compile the kernel + modules and run QEMU | never loads krunc.ko — only builds + launches QEMU |
| **QEMU guest** | the disposable kernel that actually loads krunc | this is where krunc runs; panics are contained here |

Any x86-64 Linux box with **KVM** works as the build host. If the build host is
itself a cloud VM, it needs **nested virtualization** so the QEMU guest can use
KVM. The walkthrough below uses an Azure D-series v5 VM (which supports nested
virt), but step 2 onward is identical on any Ubuntu box.

---

## 0. Prerequisites

- An x86-64 Linux build host (Ubuntu 22.04/24.04 assumed) with `/dev/kvm`.
- ~30 GB free disk and ~8 GB RAM (16 vCPUs makes the kernel build ~5 min).
- `sudo` on the build host.
- This repo checked out at `~/krunc` on the build host (`git clone <your fork> ~/krunc`).

If your build host already has KVM and the repo, skip to **step 2**.

---

## 1. (Optional) Provision an Azure VM as the build host

Pick a size that supports **nested virtualization** (the `v5`/`v3` D- and E-series
do). 16 vCPUs keeps the kernel build short.

```sh
RG=krunc-poc-rg
LOC=eastus2
VM=krunc-vm

az group create -n "$RG" -l "$LOC"

# The two tags bypass common subscription Azure Policy denials (public IP without
# a service tag, and default outbound access). Drop them if your subscription
# does not enforce those policies.
az vm create -g "$RG" -n "$VM" \
  --image Ubuntu2404 \
  --size Standard_D16ds_v5 \
  --admin-username azureuser \
  --generate-ssh-keys \
  --tags AllowPublicIPWithoutServiceTag=true AllowVnetDefaultOutboundAccess=true

# Lock SSH (port 22) to *your* IP only.
MYIP=$(curl -s https://api.ipify.org)
az network nsg rule create -g "$RG" --nsg-name "${VM}NSG" \
  --name allow-my-ssh --priority 100 --access Allow --direction Inbound \
  --protocol Tcp --destination-port-ranges 22 --source-address-prefixes "$MYIP/32"

IP=$(az vm show -g "$RG" -n "$VM" -d --query publicIps -o tsv)
echo "ssh azureuser@$IP"
```

Copy the repo up and SSH in:

```sh
rsync -az --exclude userspace/target --exclude '.git' ~/krunc/ azureuser@"$IP":~/krunc/
ssh azureuser@"$IP"
```

> Some Azure hosts expose `/dev/kvm` only to root. If step 5 complains it is not
> writable, run `sudo chmod 666 /dev/kvm` (resets on reboot).

---

## 2. Install the toolchain

On the build host:

```sh
cd ~/krunc
scripts/vm-setup.sh
```

This installs the kernel build deps, QEMU, `busybox-static`, `clang`/`lld`, and
`rustup` (no default toolchain yet — the next step pins the exact one the kernel
wants).

---

## 3. Fetch the kernel source and pin Rust

krunc was developed against **linux-6.18**. Any recent kernel with Rust support
should work, but 6.18 is the known-good tree.

```sh
cd ~
curl -O https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.tar.xz
tar xf linux-6.18.tar.xz          # -> ~/linux-6.18

# Install the exact rustc + bindgen this kernel requires, with rust-src.
~/krunc/scripts/pin-rust.sh ~/linux-6.18
```

---

## 4. Build the (vanilla) kernel

```sh
cd ~/krunc
REPO=~/krunc KSRC=~/linux-6.18 scripts/build-kernel.sh
```

This configures `defconfig` + `kvm_guest.config` and enables, among others:

- `CONFIG_RUST` — so `krunc.ko` (a Rust module) can load;
- `CONFIG_KPROBES` + `CONFIG_KALLSYMS_ALL` — so the helper module can resolve the
  non-exported kernel primitives at load time;
- namespaces, cgroup v2 (pids/memory/cpu), overlayfs, devtmpfs, initramfs.

**No krunc source is added to the kernel tree** — it is a stock build with those
config flags. Takes ~5 min on 16 cores. Output: `~/linux-6.18/arch/x86/boot/bzImage`.

---

## 5. Build krunc, assemble the initramfs, and run the demo

```sh
cd ~/krunc
scripts/run-test.sh
```

`run-test.sh` is the fast inner loop. It:

1. builds **both** modules — `krunc_helper.ko` (the C kallsyms shim) and
   `krunc.ko` (the Rust runtime) — via `scripts/build-module.sh`;
2. builds the static (musl) **`krunc` CLI** via `scripts/build-cli.sh`;
3. assembles a busybox initramfs containing both `.ko`s, the CLI, and an example
   OCI bundle (`scripts/make-initramfs.sh`);
4. boots the kernel under QEMU; the guest `/init` loads `krunc_helper.ko` then
   `krunc.ko` and runs the demo, then powers off.

You should see four demos scroll by: an isolated container via the raw text
interface, a launch+kill, the **OCI lifecycle via the `krunc` CLI** with the full
confinement stack (capabilities dropped, `no_new_privs`, masked/read-only paths,
cgroup pids/memory/cpu limits enforced from the host's view), and a clean module
unload — with **no kernel panics**.

---

## 6. Play with it by hand

Boot to an interactive shell with the module already loaded:

```sh
cd ~/krunc
scripts/run-interactive.sh
```

Inside the guest you have `busybox`, `/dev/krunc`, the `krunc` CLI, and an example
bundle at `/bundle`. Try the OCI lifecycle (the interface containerd speaks):

```sh
krunc create demo --bundle /bundle      # set up the container, block before exec
krunc state  demo                        # -> "status": "created"
krunc start  demo                        # release -> exec the entrypoint
krunc list
krunc kill   demo KILL
krunc delete demo
```

Run an ad-hoc command in a fresh container (note the `--` before the program — the
CLI treats leading-dash tokens after it as the container's argv, not krunc flags):

```sh
krunc run --rootfs /bundle/rootfs -- /bin/sh -c 'echo "hello from PID $$"; id; ls /'
```

Or drive the kernel directly through its raw text ABI:

```sh
echo 'run rootfs=/containers/demo host=h exec=/bin/sh arg=/init.sh' > /dev/krunc
cat /dev/krunc                           # list the containers the kernel tracks
```

Quit the guest with `poweroff -f`.

---

## 7. (Optional) Drive krunc from real containerd

krunc is runc-CLI-compatible, so containerd's `io.containerd.runc.v2` shim can use
it as the runtime binary:

```sh
cd ~/krunc
scripts/setup-containerd-image.sh        # stage containerd + nerdctl + a busybox image (once)
scripts/run-containerd.sh                # boot a guest where containerd/nerdctl drive krunc
```

krunc is a **strict** runtime: it rejects any `config.json` property it cannot
honor spec-faithfully (e.g. `linux.seccomp`, the device cgroup, `sysctls`), so
default `ctr`/`nerdctl` configs are refused by design. Use a reduced runtime
config within krunc's supported subset.

---

## How it works

A `write()`/`ioctl` to `/dev/krunc` runs in the caller's context; the Rust module
parses a tiny spec and `krunc_spawn()`s a task (a `kernel_clone` without
`CLONE_VM`) into fresh namespaces — PID 1 of a new PID namespace, exactly like the
kernel makes the real `init` at boot. That task, in kernel context, sets the
hostname, enters the rootfs, mounts a private `/proc`+`/sys`, applies the OCI
mounts, masks/read-only-remounts sensitive paths, places itself in a cgroup, drops
capabilities + sets `no_new_privs` + the target uid/gid, then `kernel_execve()`s
the entrypoint. All orchestration happens in the kernel.

The primitives mainline does not export to modules (`kernel_clone`,
`kernel_execve`, `set_fs_root`, `path_mount`, the cred helpers, …) are provided by
**`krunc_helper.ko`**, a small C sibling module that resolves them at load time via
a `kprobe → kallsyms_lookup_name` bootstrap and re-exports thin `krunc_*` wrappers.
It is loaded before `krunc.ko`. This is what lets krunc run on a **vanilla
`CONFIG_RUST` kernel with no source patch** — only the config flags above. See
[`docs/DESIGN.md`](docs/DESIGN.md) and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Troubleshooting

- **`/dev/kvm` not writable / QEMU falls back to slow TCG** — `sudo chmod 666
  /dev/kvm`. On a cloud build host, confirm the size supports nested virt.
- **`CONFIG_RUST` not enabled after `build-kernel.sh`** — the build silently
  disables Rust if `rustc`/`bindgen` are not the versions the kernel wants. Re-run
  `scripts/pin-rust.sh ~/linux-6.18` and rebuild. Make sure `source ~/.cargo/env`
  is in effect and `LLVM=1` (the scripts set it).
- **`insmod krunc_helper.ko` fails with "cannot resolve …"** — your kernel lacks
  `CONFIG_KPROBES` or `CONFIG_KALLSYMS_ALL`; rebuild with `build-kernel.sh` (it
  enables both). `KALLSYMS_ALL` is required because one resolved symbol (`uts_sem`)
  is a data object.
- **`insmod krunc.ko` fails with "unknown symbol in module"** — load
  `krunc_helper.ko` **first** (`krunc.ko` depends on its exports).
- **Azure `az` commands fail with a policy denial** — add the tags shown in step 1.
- **SSH times out after the VM restarts** — re-add the NSG rule (your IP may have
  changed); the VM keeps the same public IP unless deallocated.

---

## Teardown

```sh
# Stop billing for the Azure VM (keeps the disk; restart later with `az vm start`).
az vm deallocate -g krunc-poc-rg -n krunc-vm

# Or delete everything.
az group delete -n krunc-poc-rg --yes --no-wait
```

Nothing is installed on the build host kernel, so there is nothing to undo there.
