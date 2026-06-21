Agent completed. agent_id: testing-research, agent_type: research, status: completed, description: Research OCI conformance + containerd test tooling, elapsed: 654s, total_turns: 0, duration: 478s

I now have all the raw material needed. Let me compile the comprehensive research report and testing plan.

---

## Summary

The OCI runtime testing ecosystem divides cleanly into three strata: (1) **conformance verification** via `opencontainers/runtime-tools` (TAP-based, runs a compiled `runtimetest` probe inside each container), (2) **integration testing** in Rust/C runtimes (youki's `contest` framework mirrors the Go `RuntimeInsideValidate`/`RuntimeOutsideValidate` pattern but is Rust-native and runtime-agnostic), and (3) **end-to-end plumbing** via containerd's `ctr run --runc-binary` flag or the `BinaryName` config option. All security assertions follow a consistent principle: **the kernel is the ground truth**, so every claim must be verified by reading `/proc/<pid>/status`, `/sys/fs/cgroup/…`, or attempting a syscall that should be blocked.

---

## Repositories Discovered

| Repo | Purpose |
|---|---|
| `opencontainers/runtime-tools` | Official OCI conformance suite — spec generator + `runtimetest` probe binary |
| `opencontainers/runc` | Reference runtime; bats-based integration tests |
| `youki-dev/youki` | Rust OCI runtime; full test suite in `tests/contest/` |
| `containers/crun` | C OCI runtime |
| `containerd/containerd` | Container daemon; config.toml runtime registration |
| `opencontainers/image-spec` | OCI Image Layout specification |

---

## Part 1 — opencontainers/runtime-tools Conformance Suite

### Architecture

**Source:** `opencontainers/runtime-tools:README.md`, `opencontainers/runtime-tools:Makefile`

The suite has two compiled artifacts:

1. **`runtimetest`** — a statically-linked binary that runs *inside* the container. It reads `config.json` from the bundle, then validates the live process environment against the spec (capabilities, rlimits, seccomp, masked paths, readonly FS, sysctls, etc.). Output is TAP.

2. **`validation/*.t`** — one Go binary per property class. Each binary:
   - Creates a spec via `util.GetDefaultGenerator()` → `generate.Generator`
   - Configures the spec (e.g., `g.SetRootReadonly(true)`)
   - Calls `RuntimeInsideValidate` or `RuntimeOutsideValidate`
   - Emits TAP output consumed by `node-tap` or `prove`

The `RUNTIME` environment variable selects the runtime binary. `RuntimeInsideValidate` copies `runtimetest` into the bundle, then calls `$RUNTIME create` → `$RUNTIME start`, waits for exit, reads stdout.

**Source:** `opencontainers/runtime-tools:validation/util/test.go:180-250` — `RuntimeInsideValidate`:
```go
func RuntimeInsideValidate(g *generate.Generator, t *tap.T, f PreFunc) (err error) {
    bundleDir, _ := PrepareBundle()    // untars rootfs-amd64.tar.gz
    r, _ := NewRuntime(RuntimeCommand, bundleDir)
    r.SetConfig(g)
    fileutils.CopyFile("runtimetest", filepath.Join(r.BundleDir, "runtimetest"))
    r.SetID(uuid.NewString())
    r.Create()       // calls: $RUNTIME create <id> --bundle <dir>
    r.Start()        // calls: $RUNTIME start <id>
    WaitingForStatus(r, LifecycleStatusStopped, 10*time.Second, 1*time.Second)
    stdout, stderr, _ := r.ReadStandardStreams()
    // stdout is the TAP output from runtimetest
    t.Ok(!strings.Contains(string(stdout), "not ok"), g.Config.Annotations["TestName"])
}
```

`RuntimeOutsideValidate` creates the container, then calls an `AfterFunc(spec, t, state)` on the host (used for cgroup verification — reads `/sys/fs/cgroup/…`). Source: `opencontainers/runtime-tools:validation/util/test.go:252-307`.

### Build and Run Commands

```bash
# 1. Clone and build
git clone https://github.com/opencontainers/runtime-tools
cd runtime-tools
make runtimetest validation-executables
# Produces: ./runtimetest  and  ./validation/**/*.t

# 2. Run the full suite against krunc
sudo RUNTIME=/usr/local/bin/krunc make localvalidation

# 3. Run a single test (TAP output)
sudo RUNTIME=/usr/local/bin/krunc ./validation/process_capabilities/process_capabilities.t

# 4. Run a single test and see detailed TAP
sudo RUNTIME=/usr/local/bin/krunc validation/linux_seccomp/linux_seccomp.t

# 5. Parallel run with prove
sudo make TAPTOOL='prove -Q -j4' RUNTIME=/usr/local/bin/krunc localvalidation

# 6. Run only specific test categories
sudo VALIDATION_TESTS='validation/linux_seccomp.t validation/process_capabilities.t validation/root_readonly_true.t validation/linux_masked_paths.t validation/linux_cgroups_memory.t' \
     RUNTIME=/usr/local/bin/krunc make localvalidation
```

### What Each Test Checks (with assertions)

#### Capabilities
**Source:** `opencontainers/runtime-tools:cmd/runtimetest/main.go:272-321` — `validateCapabilities()`

Inside the container, `runtimetest` calls `capability.NewPid2(0)` (which reads `/proc/self/status` fields `CapBnd`, `CapEff`, `CapInh`, `CapPrm`, `CapAmb` as hex bitmasks), then for every kernel capability checks `processCaps.Get(capType, cap)` against the spec. **Test assertions:** For every cap in `spec.process.capabilities.effective`, it MUST be set in the process's effective set; for every cap NOT listed, it MUST be absent.

```go
for _, capType := range []struct{ capType capability.CapType; config []string }{
    {capability.BOUNDING,    spec.Process.Capabilities.Bounding},
    {capability.EFFECTIVE,   spec.Process.Capabilities.Effective},
    {capability.INHERITABLE, spec.Process.Capabilities.Inheritable},
    {capability.PERMITTED,   spec.Process.Capabilities.Permitted},
    {capability.AMBIENT,     spec.Process.Capabilities.Ambient},
} {
    for _, cap := range supportedCaps {
        capKey := fmt.Sprintf("CAP_%s", strings.ToUpper(cap.String()))
        expectedSet := expectedCaps[capKey]
        actuallySet := processCaps.Get(capType.capType, cap)
        c.harness.Ok(expectedSet == actuallySet, ...)
    }
}
```
**Proof from outside:** `grep CapEff /proc/<pid>/status` — the hex value must match the expected bitmask. E.g., no caps = `0000000000000000`; all caps = `000001ffffffffff`.

#### Seccomp
**Source:** `opencontainers/runtime-tools:validation/linux_seccomp/linux_seccomp.go` — sets `getcwd` → `SCMP_ACT_ERRNO`:
```go
g.SetDefaultSeccompAction("allow")
g.SetSyscallAction(seccomp.SyscallOpts{Action: "errno", Syscall: "getcwd"})
err = util.RuntimeInsideValidate(g, t, nil)
```
**Inside container (`runtimetest`):** Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:481-497`:
```go
func (c *complianceTester) validateSeccomp(spec *rspec.Spec) error {
    for _, sys := range spec.Linux.Seccomp.Syscalls {
        if sys.Action == "SCMP_ACT_ERRNO" {
            for _, name := range sys.Names {
                if name == "getcwd" {
                    _, err := os.Getwd()   // calls getcwd(2)
                    if err == nil {
                        c.harness.Skip(1, "getcwd did not return an error")
                    }
                }
            }
        }
    }
}
```
**Proof:** `getcwd()` returns `EPERM` (or `ENOSYS` depending on the filter's `errnoRet`). The test validates the syscall is blocked by attempting it.

#### Masked Paths
**Source:** `opencontainers/runtime-tools:validation/linux_masked_paths/linux_masked_paths.go` sets `g.AddLinuxMaskedPaths("/masked-dir")`, etc.

**Inside container:** Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:460-478` — `validateMaskedPaths()`:
```go
for _, maskedPath := range spec.Linux.MaskedPaths {
    readable, err := testReadAccess(maskedPath)
    c.harness.Ok(!readable, fmt.Sprintf("cannot read masked path %q", maskedPath))
}
```
`testReadAccess` tries `os.ReadDir` or `os.Open` + reads 1 byte. A masked path (bound to `/dev/null`) returns 0 bytes on read → `readable = false`.

**Proof:** Inside container: `cat /proc/kcore` returns empty; `ls /proc/interrupts` returns empty. From outside: `stat /proc/<pid>/root/masked-path` shows it's bound to a null device.

#### Readonly Rootfs
**Source:** `opencontainers/runtime-tools:validation/root_readonly_true/root_readonly_true.go`:
```go
g.SetRootReadonly(true)
err = util.RuntimeInsideValidate(g, nil, nil)
```
**Inside container:** Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:378-397` — `validateRootFS()`:
```go
writable, err := testDirectoryWriteAccess("/")  // tries os.CreateTemp("/", "Test")
if spec.Root.Readonly {
    c.harness.Ok(!writable, "root filesystem is readonly")
}
```
**Proof:** Inside container: `touch /test-file` returns `EROFS`. From outside: `findmnt -o OPTIONS /proc/<pid>/root | grep ro` shows `ro` in options.

#### Cgroup Memory Limits (from host)
**Source:** `opencontainers/runtime-tools:validation/linux_cgroups_memory/linux_cgroups_memory.go` calls `RuntimeOutsideValidate` with `util.ValidateLinuxResourcesMemory`:
```go
g.SetLinuxCgroupsPath(cgroups.AbsCgroupPath)
g.SetLinuxResourcesMemoryLimit(50593792)
g.SetLinuxResourcesMemorySwappiness(10)
err = util.RuntimeOutsideValidate(g, t, util.ValidateLinuxResourcesMemory)
```
**Host-side assertion** (source: `opencontainers/runtime-tools:validation/util/linux_resources_memory.go`): reads `/sys/fs/cgroup/memory/<cgrouppath>/memory.limit_in_bytes` and compares to spec value.

**Proof from outside:** `cat /sys/fs/cgroup/memory/<cgrouppath>/memory.limit_in_bytes` must equal `50593792`.

#### Hostname, Rlimits, Sysctls, UID/GID Mappings, OOM Score
All checked inside the container by `runtimetest`:
- **Hostname:** `os.Hostname()` == `spec.Hostname` — Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:~325-345`
- **Rlimits:** `syscall.Getrlimit(RLIMIT_NOFILE, &rl)` → checks `rl.Cur == spec.rlimit.Soft`, `rl.Max == spec.rlimit.Hard`
- **Sysctls:** reads `/proc/sys/net/ipv4/ip_forward` (for `net.ipv4.ip_forward`) — Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:408-430`
- **OOM Score:** reads `/proc/self/oom_score_adj` — Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:500-525`
- **UID/GID maps:** reads `/proc/self/uid_map`, `/proc/self/gid_map` — Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:540-600`

---

## Part 2 — youki/runc/crun Test Approaches

### youki `contest` Framework (Rust)

**Architecture** (Source: `youki-dev/youki:tests/contest/contest/README.md`):

```
TestManager
  └── TestGroup ("seccomp", "cgroup_v1_pids", ...)
       └── Test / ConditionalTest (fn() -> TestResult)
```

Two core utilities mirroring the Go suite:
- `test_inside_container(spec, opts, pre_fn)` → mirrors `RuntimeInsideValidate`
- `test_outside_container(spec, post_fn)` → mirrors `RuntimeOutsideValidate`

Both utilities: create a temp dir, write `config.json`, run `$RUNTIME create <uuid> --bundle <dir>`, run `$RUNTIME start <uuid>`, optionally run the post/pre hook, then `$RUNTIME kill`+`$RUNTIME delete`. Source: `youki-dev/youki:tests/contest/contest/src/utils/test_utils.rs`.

**Run command** (binary takes `--runtime` and `--runtimetest` paths):
```bash
cd tests/contest
cargo build --release
sudo ./target/release/contest run \
  --runtime /path/to/krunc \
  --runtimetest /path/to/runtimetest
# Run specific group:
sudo ./target/release/contest run \
  --runtime /path/to/krunc \
  --runtimetest ./runtimetest \
  -t seccomp process_capabilities_fail readonly_paths cgroup_v1_pids
# List available tests:
./target/release/contest list
```

### Seccomp Test (Rust)

**Source:** `youki-dev/youki:tests/contest/contest/src/tests/seccomp/mod.rs`
```rust
fn seccomp_test() -> TestResult {
    let spec = SpecBuilder::default()
        .linux(LinuxBuilder::default()
            .seccomp(LinuxSeccompBuilder::default()
                .default_action(LinuxSeccompAction::ScmpActAllow)
                .syscalls(vec![LinuxSyscallBuilder::default()
                    .names(vec![String::from("getcwd")])
                    .action(LinuxSeccompAction::ScmpActErrno)
                    .build().unwrap()])
                .build().unwrap())
            .build().unwrap())
        .process(ProcessBuilder::default()
            .args(vec!["runtimetest".to_string(), "seccomp".to_string()])
            .build().unwrap())
        .build().unwrap();

    test_inside_container(&spec, &CreateOptions::default(), &|_| Ok(()))
}
```
Inside the container, `runtimetest seccomp` calls (source: `youki-dev/youki:tests/contest/runtimetest/src/tests.rs:~L15500`):
```rust
pub fn validate_seccomp(spec: &Spec) {
    if linux.seccomp().is_some() {
        if let Err(errno) = getcwd() {
            if errno != Errno::EPERM {
                eprintln!("'getcwd()' failed with unexpected error code '{errno}', expected 'EPERM'");
            }
            // EPERM = test passed: syscall was blocked
        } else {
            eprintln!("'getcwd()' syscall succeeded. It was expected to fail due to seccomp policies.");
        }
    }
}
```
**Assertion:** `getcwd(2)` must return `EPERM` (or optionally `ENOSYS` if using `SCMP_ACT_KILL`).

### Capability Fail Test (Rust)

**Source:** `youki-dev/youki:tests/contest/contest/src/tests/process_capabilities_fail/process_capabilities_fail_test.rs`

This test directly patches the serialized `config.json` to inject an invalid capability name `"TEST_CAP"`, then attempts container creation:
```rust
fn process_capabilities_fail_test() -> TestResult {
    let spec = test_result!(create_spec());
    let result = test_inside_container(&spec, &CreateOptions::default(), &|bundle| {
        let spec_path = bundle.join("../config.json");
        let mut spec_json: Value = serde_json::from_str(&fs::read_to_string(spec_path.clone())?)?;
        // Replace bounding and effective caps with invalid name
        for path in &["/process/capabilities/bounding", "/process/capabilities/effective"] {
            if let Some(arr) = spec_json.pointer_mut(path).and_then(|v| v.as_array_mut()) {
                for cap in arr.iter_mut() { *cap = Value::String("TEST_CAP".to_string()); }
            }
        }
        fs::write(spec_path, serde_json::to_string_pretty(&spec_json)?)?;
        Ok(())
    });
    match result {
        TestResult::Failed(e) => {
            let err_str = format!("{:?}", e);
            if err_str.contains("no variant for TEST_CAP")          // youki error
            || err_str.contains("ignoring unknown or unavailable capabilities: [TEST_CAP]")  // runc
            { TestResult::Passed } else { TestResult::Failed(e) }
        }
        TestResult::Passed => TestResult::Failed(anyhow!("container creation succeeded unexpectedly.")),
        _ => result,
    }
}
```
**Assertion:** Runtime MUST fail (or warn about) unknown capability names.

### Readonly Paths (Rust)

**Source:** `youki-dev/youki:tests/contest/contest/src/tests/readonly_paths/readonly_paths_tests.rs`

Setup: specifies `/readonly_dir`, `/readonly_file`, etc. in `linux.readonlyPaths`.
Inside container (`runtimetest readonly_paths`), source: `youki-dev/youki:tests/contest/runtimetest/src/tests.rs:45-85`:
```rust
pub fn validate_readonly_paths(spec: &Spec) {
    for path in ro_paths {
        // Read access should work
        if let Err(e) = test_read_access(path) {
            let errno = Errno::from_raw(e.raw_os_error().unwrap());
            if errno != Errno::ENOENT { eprintln!("unexpected error on read: {e:?}"); return; }
        }
        // Write access MUST fail with EROFS
        if let Err(e) = test_write_access(path) {
            let errno = Errno::from_raw(e.raw_os_error().unwrap());
            if errno == Errno::ENOENT || errno == Errno::EROFS { /* expected */ }
            else { eprintln!("unexpected write error: {e:?}"); return; }
        } else {
            eprintln!("path {path} expected to NOT be writable, found writable");
        }
    }
}
```
**Assertion:** Write to a readonly-bind-mounted path returns `EROFS`.

### Cgroup Pids Limit — Host-Side Verification

**Source:** `youki-dev/youki:tests/contest/contest/src/tests/cgroups/pids.rs`
```rust
fn check_pid_limit_set(cgroup_name: &str, expected: i64) -> Result<()> {
    let cgroup_path = PathBuf::from(CGROUP_ROOT)   // "/sys/fs/cgroup"
        .join("pids/runtime-test")
        .join(cgroup_name)
        .join("pids.max");
    let content = fs::read_to_string(&cgroup_path)?;
    let actual: i64 = content.trim().parse()?;
    if expected != actual {
        bail!("expected pids.max={}, found {}", expected, actual);
    }
    Ok(())
}
fn can_run() -> bool { Path::new("/sys/fs/cgroup/pids").exists() }
```
**Assertion:** `cat /sys/fs/cgroup/pids/runtime-test/<name>/pids.max` == requested limit.

### Cgroup Memory — Host-Side Verification

**Source:** `youki-dev/youki:tests/contest/contest/src/tests/cgroups/memory.rs`
```rust
const CGROUP_MEMORY_LIMIT: &str = "/sys/fs/cgroup/memory/memory.limit_in_bytes";
const CGROUP_MEMORY_SWAPPINESS: &str = "/sys/fs/cgroup/memory/memory.swappiness";

fn can_run() -> bool {
    Path::new(CGROUP_MEMORY_LIMIT).exists()
    && Path::new(CGROUP_MEMORY_SWAPPINESS).exists()
}
```
**Assertion:** read `memory.limit_in_bytes` from the container's cgroup path; value must match spec.

### runc Integration Tests (bats)

**Source:** `opencontainers/runc:tests/integration/README.md`

```bash
# All integration tests (requires Docker):
make integration

# Direct on host:
sudo bats tests/integration

# Specific test file:
sudo bats tests/integration/spec.bats

# Install bats:
git clone https://github.com/bats-core/bats-core && cd bats-core && sudo ./install.sh /usr/local
```
Tests use bash functions from `tests/integration/helpers.bash`. Pattern:
```bash
@test "runc run with readonly rootfs" {
    update_config '.root.readonly = true'
    runc run --detach --pid-file /tmp/runc-pid.txt test_busybox
    [ "$status" -eq 0 ]
    run runc exec test_busybox touch /ro_test_file
    [ "$status" -ne 0 ]    # must fail
}
```

---

## Part 3 — containerd Integration

### Config.toml Runtime Registration

**Source:** `containerd/containerd:docs/man/containerd-config.toml.5.md`

```toml
# /etc/containerd/config.toml  (version 2)
version = 2

[plugins."io.containerd.grpc.v1.cri".containerd.runtimes.krunc]
  runtime_type = "io.containerd.runc.v2"
  [plugins."io.containerd.grpc.v1.cri".containerd.runtimes.krunc.options]
    BinaryName = "/usr/local/bin/krunc"
```

`BinaryName` specifies the path to the actual runtime binary invoked by the shim (`io.containerd.runc.v2` acts as the shim; it calls `BinaryName` instead of the default `runc`).

After editing config.toml:
```bash
sudo systemctl restart containerd
# Verify it parsed:
sudo containerd config dump | grep -A5 'krunc'
```

### Running Containers via `ctr`

```bash
# Direct override (no config.toml change needed):
sudo ctr run --rm \
  --runtime io.containerd.runc.v2 \
  --runc-binary /usr/local/bin/krunc \
  docker.io/library/busybox:latest \
  krunc-test-1 \
  sh -c 'echo hello from krunc'

# With the registered runtime handler:
sudo ctr run --rm \
  --runtime io.containerd.runc.v2 \
  docker.io/library/busybox:latest \
  krunc-test-2 \
  sh
# (requires BinaryName set in config.toml)

# Check container state
sudo ctr tasks ls
sudo ctr containers ls
```

### Offline Image Import (for CI/Hermetic Tests)

```bash
# ── OPTION A: docker save (Docker/legacy format) ──
docker pull busybox:latest
docker save busybox:latest -o busybox-docker.tar
sudo ctr image import busybox-docker.tar

# ── OPTION B: skopeo to OCI archive ──
skopeo copy docker://busybox:latest oci-archive:busybox-oci.tar
sudo ctr image import busybox-oci.tar

# ── OPTION C: skopeo to local OCI layout ──
skopeo copy docker://busybox:latest oci:./busybox-layout:latest
tar -C busybox-layout -cf busybox-layout.tar .
sudo ctr image import --base-name busybox:latest busybox-layout.tar

# Verify it's present:
sudo ctr images ls | grep busybox
```

**Source:** `containerd/containerd:cmd/ctr/commands/images/import.go` — accepts both Docker legacy archive and OCI image archive formats.

---

## Part 4 — Constructing a Minimal OCI Image by Hand

**Source:** `opencontainers/image-spec:image-layout.md` — required structure:
```
<layout>/
  oci-layout              # {"imageLayoutVersion": "1.0.0"}
  index.json              # OCI image index (entry point)
  blobs/sha256/
    <config-digest>       # image config JSON
    <manifest-digest>     # image manifest JSON
    <layer-digest>        # layer tar (can be gzipped)
```

### Complete Build Script

```bash
#!/usr/bin/env bash
set -euo pipefail
OUTDIR=$(mktemp -d)
BLOBDIR="$OUTDIR/blobs/sha256"
mkdir -p "$BLOBDIR"

# ── 1. Create a minimal rootfs layer ──
# Use busybox static binary for a real test payload
ROOTFS=$(mktemp -d)
# For a truly empty layer:
# tar -C "$ROOTFS" -czf /tmp/layer.tar.gz .
# Or for a useful layer, copy a static binary:
cp "$(which busybox)" "$ROOTFS/sh" 2>/dev/null || true
chmod +x "$ROOTFS/sh"
tar -C "$ROOTFS" -czf /tmp/layer.tar.gz .
LAYER_DGST=$(sha256sum /tmp/layer.tar.gz | awk '{print $1}')
LAYER_SIZE=$(stat -c%s /tmp/layer.tar.gz)
# Uncompressed digest for config.rootfs.diff_ids
LAYER_UCMP_DGST=$(gunzip -c /tmp/layer.tar.gz | sha256sum | awk '{print $1}')
cp /tmp/layer.tar.gz "$BLOBDIR/$LAYER_DGST"

# ── 2. Image config ──
CONFIG_JSON=$(cat <<EOF
{
  "architecture": "amd64",
  "os": "linux",
  "config": {"Cmd": ["/sh"]},
  "rootfs": {
    "type": "layers",
    "diff_ids": ["sha256:${LAYER_UCMP_DGST}"]
  },
  "history": [{"created_by": "krunc test image"}]
}
EOF
)
echo "$CONFIG_JSON" > /tmp/config.json
CONFIG_DGST=$(sha256sum /tmp/config.json | awk '{print $1}')
CONFIG_SIZE=$(stat -c%s /tmp/config.json)
cp /tmp/config.json "$BLOBDIR/$CONFIG_DGST"

# ── 3. Image manifest ──
MANIFEST_JSON=$(cat <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.oci.image.config.v1+json",
    "size": ${CONFIG_SIZE},
    "digest": "sha256:${CONFIG_DGST}"
  },
  "layers": [{
    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
    "size": ${LAYER_SIZE},
    "digest": "sha256:${LAYER_DGST}"
  }]
}
EOF
)
echo "$MANIFEST_JSON" > /tmp/manifest.json
MANIFEST_DGST=$(sha256sum /tmp/manifest.json | awk '{print $1}')
MANIFEST_SIZE=$(stat -c%s /tmp/manifest.json)
cp /tmp/manifest.json "$BLOBDIR/$MANIFEST_DGST"

# ── 4. oci-layout marker ──
echo '{"imageLayoutVersion":"1.0.0"}' > "$OUTDIR/oci-layout"

# ── 5. index.json ──
cat > "$OUTDIR/index.json" <<EOF
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.index.v1+json",
  "manifests": [{
    "mediaType": "application/vnd.oci.image.manifest.v1+json",
    "size": ${MANIFEST_SIZE},
    "digest": "sha256:${MANIFEST_DGST}",
    "annotations": {
      "org.opencontainers.image.ref.name": "latest"
    }
  }]
}
EOF

# ── 6. Package as OCI archive and import ──
tar -C "$OUTDIR" -cf /tmp/krunc-test-image.tar .
sudo ctr image import --base-name krunc-test:latest /tmp/krunc-test-image.tar

echo "Image ready: krunc-test:latest"
echo "Import verified:"
sudo ctr images ls | grep krunc-test
```

**Verification:**
```bash
# Validate the layout before importing
oci-runtime-tool validate --bundle /path/to/bundle
# Or with skopeo (validates the OCI archive):
skopeo inspect oci-archive:/tmp/krunc-test-image.tar
```

---

## Part 5 — Rust Testing Patterns

### Kernel Module — RfL KUnit

**Source:** `docs.kernel.org/rust/testing.html`

KUnit tests run inside the kernel as a test suite. Rust doctests are automatically transformed into KUnit test suites at build time:

```rust
// In a kernel module's lib.rs

/// Applies the OCI spec's capability mask.
///
/// ```
/// use kernel::prelude::*;
/// use crate::capabilities::apply_cap_mask;
///
/// let result = apply_cap_mask(0xffffffffffffffff, /* drop NET_ADMIN */ 0xfffffff9ffffffff);
/// assert_eq!(result & (1 << 12), 0);  // CAP_NET_ADMIN (bit 12) must be clear
/// ```
pub fn apply_cap_mask(caps: u64, mask: u64) -> u64 { caps & mask }
```

These compile to a KUnit test suite visible in `ktap` output:
```
ok 1 rust_doctest_kernel_capabilities_rs_0
```

For explicit KUnit test suites (kernel-only unit tests):
```rust
#[cfg(CONFIG_KUNIT)]
mod tests {
    use super::*;
    use kernel::kunit_assert_eq;

    #[test_case]
    fn test_cgroup_path_parse() {
        let path = parse_cgroup_path("/krunc/test-1").unwrap();
        kunit_assert_eq!(path.len(), 2);
    }
}
```

**Build and run:**
```bash
# Run Rust doctests as KUnit (requires KUnit config):
make LLVM=1 KUNIT_FILTER_GLOB='rust_doctests*' -j$(nproc)
./tools/testing/kunit/kunit.py run --kunitconfig=.kunit/.kunitconfig
```

### CLI / Userspace Rust — `assert_cmd` Integration Tests

**Source:** `docs.rs/assert_cmd/latest/assert_cmd/`

**Cargo.toml:**
```toml
[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
serde_json = "1"
insta = { version = "1", features = ["json", "yaml"] }   # golden-file tests
```

**Pattern — lifecycle tests:**
```rust
// tests/lifecycle.rs
use assert_cmd::Command;
use predicates::str::contains;
use std::fs;
use tempfile::TempDir;

fn make_bundle() -> TempDir {
    let dir = TempDir::new().unwrap();
    // copy rootfs + write config.json to dir.path()
    // ...
    dir
}

#[test]
fn test_create_then_state() {
    let bundle = make_bundle();
    let id = "krunc-test-lifecycle-001";

    // krunc create
    Command::cargo_bin("krunc").unwrap()
        .args(["create", "--bundle", bundle.path().to_str().unwrap(), id])
        .assert()
        .success();

    // krunc state → JSON with "status": "created"
    let out = Command::cargo_bin("krunc").unwrap()
        .args(["state", id])
        .assert()
        .success()
        .get_output()
        .stdout.clone();
    let state: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(state["status"], "created");

    // krunc delete
    Command::cargo_bin("krunc").unwrap()
        .args(["delete", id])
        .assert()
        .success();
}
```

**Pattern — spec translation golden-file tests:**
```rust
// tests/spec_translation.rs
use insta::assert_json_snapshot;

#[test]
fn test_translate_seccomp_policy() {
    let input = r#"{
        "seccomp": {
            "defaultAction": "SCMP_ACT_ALLOW",
            "syscalls": [{"names": ["getcwd"], "action": "SCMP_ACT_ERRNO"}]
        }
    }"#;
    let result = krunc::spec::translate(input).unwrap();
    assert_json_snapshot!("seccomp_translation", result);
    // First run: creates tests/snapshots/seccomp_translation.snap
    // Subsequent runs: diffs against it
}
```

**Pattern — unit tests for spec parsing:**
```rust
// src/spec.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_caps_drops_unknown() {
        let spec_json = r#"{"process": {"capabilities": {"effective": ["CAP_SYS_ADMIN"]}}}"#;
        let spec = parse_spec(spec_json).unwrap();
        assert!(spec.process.capabilities.effective.contains(&"CAP_SYS_ADMIN".to_string()));
        assert!(!spec.process.capabilities.effective.contains(&"CAP_NET_ADMIN".to_string()));
    }

    #[test]
    fn test_masked_path_requires_absolute() {
        let result = validate_masked_path("relative/path");
        assert!(result.is_err());
    }
}
```

---

## Part 6 — Concrete krunc Testing Plan

### Tier 1: OCI Conformance (runtime-tools suite)

**Goal:** Prove krunc passes the full OCI spec.

```bash
# Setup
git clone https://github.com/opencontainers/runtime-tools
cd runtime-tools && make runtimetest validation-executables

# Run full suite, save results
sudo RUNTIME=/usr/local/bin/krunc make localvalidation 2>&1 | tee /tmp/krunc-conformance.log

# Focus first on the security-critical tests:
SECURITY_TESTS="
  validation/process_capabilities/process_capabilities.t
  validation/process_capabilities_fail/process_capabilities_fail.t
  validation/linux_seccomp/linux_seccomp.t
  validation/linux_masked_paths/linux_masked_paths.t
  validation/root_readonly_true/root_readonly_true.t
  validation/linux_readonly_paths/linux_readonly_paths.t
  validation/linux_cgroups_memory/linux_cgroups_memory.t
  validation/linux_cgroups_pids/linux_cgroups_pids.t
  validation/linux_uid_mappings/linux_uid_mappings.t
  validation/process_rlimits/process_rlimits.t
  validation/linux_sysctl/linux_sysctl.t
  validation/hostname/hostname.t
"
for t in $SECURITY_TESTS; do
  echo "=== $t ===" 
  sudo RUNTIME=/usr/local/bin/krunc $t || echo "FAILED: $t"
done
```

### Tier 2: youki `contest` Framework

```bash
cd youki-dev/youki/tests/contest
cargo build --release -p contest -p runtimetest

# Run the security-focused groups against krunc:
sudo ./target/release/contest run \
  --runtime /usr/local/bin/krunc \
  --runtimetest ./target/release/runtimetest \
  -t seccomp \
     process_capabilities_fail \
     process_capabilities_bounding \
     readonly_paths \
     linux_masked_paths \
     root_readonly_true \
     cgroup_v1_pids \
     cgroup_v1_memory \
     uid_mappings \
     hostname \
     process_rlimits \
     lifecycle \
     create

# Full suite:
sudo ./target/release/contest run \
  --runtime /usr/local/bin/krunc \
  --runtimetest ./target/release/runtimetest
```

### Tier 3: Security Isolation Test Matrix

The following table maps **what to test → how to prove it from outside the container**.

#### A. Capabilities

**Setup:** spec with `process.capabilities.effective = ["CAP_NET_ADMIN"]` only.

```bash
# Create container with limited caps, read /proc/$PID/status
CPID=$(sudo krunc state $CONTAINER_ID | jq -r .pid)
grep CapEff /proc/$CPID/status
# Must output something like: CapEff: 0000000000001000  (bit 12 = CAP_NET_ADMIN only)

# Cross-check: decode the hex
python3 -c "
caps = 0x0000000000001000
expected = 1 << 12  # CAP_NET_ADMIN
assert caps == expected, f'unexpected caps: {hex(caps)}'
print('PASS: only CAP_NET_ADMIN set')
"

# To assert NO capabilities:
# spec: capabilities: {effective: [], bounding: [], permitted: []}
grep CapEff /proc/$CPID/status
# Expected: 0000000000000000
```

Inside container via `runtimetest`: `capability.NewPid2(0)` → `processCaps.Get(EFFECTIVE, cap)` for each supported capability. Source: `opencontainers/runtime-tools:cmd/runtimetest/main.go:272-321`.

#### B. Seccomp — Proving a syscall is blocked

```bash
# Method 1: via the conformance suite (runs inside container)
sudo RUNTIME=/usr/local/bin/krunc validation/linux_seccomp/linux_seccomp.t
# The test sets getcwd → ERRNO, then calls os.Getwd() inside container.
# TAP output: "ok 1 - seccomp action is added correctly"

# Method 2: manual proof with strace on host
sudo strace -p $CPID -e trace=getcwd 2>&1 &
sudo krunc exec $CONTAINER_ID sh -c 'pwd'
# Expected in strace output: "getcwd(...)  = -1 EPERM (Operation not permitted)"

# Method 3: proc/seccomp from outside
cat /proc/$CPID/status | grep Seccomp
# Seccomp: 2  (2 = SECCOMP_MODE_FILTER is active)
# Note: Seccomp: 0 means no filter, 1 = strict, 2 = filter
```

**Assertion:** `/proc/<pid>/status` → `Seccomp: 2` proves a BPF filter is active. Attempting the blocked syscall returns `EPERM`/`ENOSYS`.

#### C. Readonly Rootfs — Proving it's enforced

```bash
# From outside: check mount options via findmnt
CONTAINER_ROOT=$(sudo krunc state $CONTAINER_ID | jq -r '.bundle')/rootfs
findmnt --target $CONTAINER_ROOT -o OPTIONS | grep -q '\bro\b' && echo "PASS: rootfs is ro" || echo "FAIL"

# Or via /proc/<pid>/mounts inside container:
sudo nsenter -m -t $CPID -- cat /proc/1/mounts | grep "/ " | grep -q '\bro\b' && echo "PASS"

# From inside (runtimetest does this):
# Tries: os.CreateTemp("/", "Test") → expects EROFS
# Source: opencontainers/runtime-tools:cmd/runtimetest/main.go:378-397

# Manual shell test inside container:
sudo krunc exec $CONTAINER_ID touch /readonly_test_file
# Must fail: touch: /readonly_test_file: Read-only file system
echo "Exit code: $?"   # Must be non-zero
```

#### D. Masked Paths — Proving they're masked

```bash
# The masked path (e.g., /proc/kcore) is bind-mounted to /dev/null.
# From outside: check with nsenter
sudo nsenter -m -t $CPID -- stat /proc/kcore
# Should show: character special file with major:minor = 1:3 (/dev/null)
sudo nsenter -m -t $CPID -- cat /proc/kcore | wc -c
# Expected: 0 (reads nothing from /dev/null)

# OR check mountinfo from outside
grep "/proc/kcore" /proc/$CPID/mountinfo
# Should show something like: ... /dev/null /proc/kcore ...

# runtimetest validates by calling testReadAccess(maskedPath):
# Source: opencontainers/runtime-tools:cmd/runtimetest/main.go:460-478
# If reads 0 bytes → "cannot read masked path" passes
```

#### E. Cgroup Memory Limit — Proving from host

```bash
# After container start, the cgroup is visible from outside:
CGROUP_PATH=$(cat /proc/$CPID/cgroup | grep memory | cut -d: -f3)
cat /sys/fs/cgroup/memory${CGROUP_PATH}/memory.limit_in_bytes
# Must equal the value set in spec.linux.resources.memory.limit

# For cgroups v2:
cat /sys/fs/cgroup${CGROUP_PATH}/memory.max
# Must equal spec value (or "max" if unlimited)

# Pids limit:
cat /sys/fs/cgroup/pids${CGROUP_PATH}/pids.max
# Must equal spec.linux.resources.pids.limit
# Source: youki-dev/youki:tests/contest/contest/src/tests/cgroups/pids.rs

# CPU quota:
cat /sys/fs/cgroup/cpu${CGROUP_PATH}/cpu.cfs_quota_us
cat /sys/fs/cgroup/cpu${CGROUP_PATH}/cpu.cfs_period_us
# quota/period = CPU share fraction from spec
```

#### F. Namespace Isolation — Proving via inode numbers

```bash
# Each new namespace has a unique inode under /proc/<pid>/ns/
ls -la /proc/$CPID/ns/
# Expected: pid, mnt, net, ipc, uts all pointing to different inodes than the host

# Compare PID namespace:
ls -lai /proc/1/ns/pid          # host init's PID namespace inode
ls -lai /proc/$CPID/ns/pid      # container process's PID namespace inode
# They MUST differ

# UTS namespace (for hostname isolation):
ls -lai /proc/1/ns/uts
ls -lai /proc/$CPID/ns/uts
# Must differ; then inside: hostname ≠ host's hostname

# Network namespace:
ip netns identify $CPID        # shows the netns name if created
# Or:
ls -lai /proc/$CPID/ns/net   # inode must differ from host's
```

#### G. Seccomp + `CAP_SYS_ADMIN` Combination Test

```bash
# Prove that a container cannot do privileged mounts (seccomp + no caps)
sudo krunc exec $CONTAINER_ID -- mount -t tmpfs none /tmp
# Must fail: either EPERM (no CAP_SYS_ADMIN) or seccomp block

# Strace from outside to see which layer blocks it:
sudo strace -p $CPID -e trace=mount 2>&1 &
sudo krunc exec $CONTAINER_ID mount -t tmpfs none /tmp
# Look for: mount(...) = -1 EPERM
```

### Tier 4: containerd End-to-End Test

```bash
# 1. Import test image (built offline with the script above)
sudo ctr image import krunc-test-image.tar

# 2. Run with krunc
sudo ctr run --rm \
  --runtime io.containerd.runc.v2 \
  --runc-binary /usr/local/bin/krunc \
  --snapshotter overlayfs \
  krunc-test:latest \
  krunc-e2e-1 \
  sh -c 'echo "hello from krunc" && id'

# 3. Assert output
# Expected stdout: "hello from krunc" and uid=0(root) or non-root

# 4. Verify cgroup is created under containerd's cgroup prefix:
CPID=$(sudo ctr tasks ls | grep krunc-e2e-1 | awk '{print $2}')
cat /proc/$CPID/cgroup  # Should show containerd's hierarchy

# 5. Run with readonly rootfs:
sudo ctr run --rm \
  --runtime io.containerd.runc.v2 \
  --runc-binary /usr/local/bin/krunc \
  --read-only \
  krunc-test:latest \
  krunc-e2e-2 \
  sh -c 'touch /test && echo "FAIL: should be readonly" || echo "PASS: readonly enforced"'
```

### Tier 5: Rust Unit + Integration Tests for krunc CLI

**`Cargo.toml` additions:**
```toml
[dev-dependencies]
assert_cmd = "2"
predicates = "3"
tempfile = "3"
insta = { version = "1", features = ["json"] }
nix = { version = "0.29", features = ["process", "user", "fs"] }
```

**Spec translation golden tests:**
```rust
// tests/spec_translation.rs
#[test]
fn seccomp_policy_round_trips() {
    let oci_spec_json = include_str!("fixtures/seccomp-spec.json");
    let translated = krunc::spec::translate_seccomp(oci_spec_json).unwrap();
    insta::assert_json_snapshot!("seccomp_policy", translated);
}

#[test]
fn readonly_paths_in_spec() {
    let spec = krunc::spec::Builder::new()
        .readonly_paths(vec!["/proc/kcore", "/proc/sysrq-trigger"])
        .build()
        .unwrap();
    assert!(spec.linux.as_ref().unwrap().readonly_paths.as_ref().unwrap()
            .contains(&"/proc/kcore".to_string()));
}
```

**CLI integration test (assert_cmd):**
```rust
// tests/cli_test.rs
use assert_cmd::Command;
use predicates::{prelude::*, str::contains};

#[test]
fn krunc_version_exits_zero() {
    Command::cargo_bin("krunc").unwrap()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("krunc"));
}

#[test]
fn krunc_state_nonexistent_container_exits_nonzero() {
    Command::cargo_bin("krunc").unwrap()
        .args(["state", "nonexistent-xyz-123"])
        .assert()
        .failure();
}

#[test]
#[ignore = "requires root and full bundle setup"]
fn krunc_run_echo_container() {
    let bundle = setup_echo_bundle(); // creates bundle with config.json + rootfs
    Command::cargo_bin("krunc").unwrap()
        .args(["run", "--bundle", bundle.path().to_str().unwrap(), "krunc-unit-1"])
        .assert()
        .success();
}
```

---

## Gaps and Uncertainties

1. **crun test approach:** The `containers/crun` repo has tests in `tests/` but they are Alpine-build-based shell scripts (source: `containers/crun:tests/alpine-build/`), not a portable test framework — less instructive for krunc than the Go/Rust patterns above.

2. **containerd `ctr run --runc-binary`:** This flag is documented and used in practice but is specific to the `io.containerd.runc.v2` shim. Verified via the shim source in `containerd/containerd:core/runtime/v2/` — the shim passes `BinaryName` from options to the underlying OCI runtime call.

3. **Cgroups v2 vs v1:** The youki memory/pids tests shown above target cgroupsv1 paths (`/sys/fs/cgroup/memory/…`). On modern kernels with pure cgroupsv2, paths are under `/sys/fs/cgroup/<path>/memory.max` etc. Both the runtime-tools and youki tests use `can_run()` guards to detect which hierarchy is available. Verify: `mount | grep cgroup2` on your test host.

4. **`validate_seccomp` in youki runtimetest uses `Errno::EPERM`** (source: `tests.rs:15500`), while the Go `runtimetest` only checks `err != nil` (any error). The OCI spec does not mandate which errno seccomp returns — `SCMP_ACT_ERRNO` defaults to `EPERM`, but the filter can be configured to return any errno. The youki test is more specific than strictly required.

5. **KUnit `#[kunit_tests]` vs `#[cfg(CONFIG_KUNIT)] mod tests`:** The first form (`#[kunit_tests(suite)]`) is the macro-based approach added in newer kernels; the older approach uses `#[test_case]` inside a `#[cfg(CONFIG_KUNIT)]` module. As of Linux 6.x, doctests are auto-wrapped into KUnit suites. Source: `docs.kernel.org/rust/testing.html`.

6. **OCI image import format:** `ctr image import` accepts both Docker-save format (with `manifest.json` + layer directories at root) and OCI archive format (with `oci-layout` + `index.json` at root). The hand-built script above produces OCI format. Verified structurally against `opencontainers/image-spec:image-layout.md`.