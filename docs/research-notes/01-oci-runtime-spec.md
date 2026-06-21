Agent completed. agent_id: oci-spec-research, agent_type: research, status: completed, description: Research OCI runtime-spec requirements, elapsed: 355s, total_turns: 0, duration: 277s

I now have all the critical information needed. Let me compile the comprehensive reference document.

---

# OCI Runtime Specification — Authoritative Implementation Reference

**Source:** `opencontainers/runtime-spec` (commit SHA prefix: `6999a89`)
**Canonical spec files read:** `runtime.md`, `config.md`, `config-linux.md`, `features.md`, `features-linux.md`, `bundle.md`, `schema/config-schema.json`, `schema/config-linux.json`, `schema/defs.json`, `schema/defs-linux.json`, `schema/state-schema.json`

---

## 1. Container Lifecycle State Machine

### 1.1 States

> **Source:** [`opencontainers/runtime-spec:runtime.md` — "State"](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state)

The spec defines exactly **four canonical states** for the `status` field:

| Status | Meaning |
|---|---|
| `creating` | The container environment is being set up (lifecycle step 2) |
| `created` | `create` completed; environment exists; `process.args` **have NOT run** (after step 2) |
| `running` | User-specified process is executing (after lifecycle step 8) |
| `stopped` | Container process has exited (lifecycle step 10) |

**MUST:** Additional values MAY be defined by the runtime but MUST represent new states not overlapping the four above.

### 1.2 The `state` JSON Object

> **Source:** [`runtime.md` — "State"](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#state); **Schema:** [`schema/state-schema.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/state-schema.json)

```json
{
    "ociVersion": "0.2.0",       // string, REQUIRED — semver of spec
    "id":         "oci-container1", // string, REQUIRED — unique on this host
    "status":     "running",     // string, REQUIRED — one of the four states
    "pid":        4422,          // int, REQUIRED when status=created|running on Linux
    "bundle":     "/containers/redis", // string, REQUIRED — absolute path to bundle dir
    "annotations": { "myKey": "myValue" } // map, OPTIONAL
}
```

**REQUIRED fields** per `state-schema.json`: `ociVersion`, `id`, `status`, `bundle`.  
**`pid`**: REQUIRED when `status` is `created` or `running` on Linux; OPTIONAL on other platforms. For hooks in the runtime namespace, pid is as seen by the runtime; for hooks in the container namespace, pid is as seen by the container.  
**`annotations`**: MAY be absent or an empty map if none set.  
**Serialization:** When serialized, MUST adhere to `schema/state-schema.json` (JSON Schema draft-04).

### 1.3 Operations — What Each MUST Do

> **Source:** [`runtime.md` — "Operations"](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#operations)

#### `state <container-id>`
- MUST generate an error if container ID is missing.
- Querying a non-existent container MUST generate an error.
- MUST return the state JSON as specified.

#### `create <container-id> <path-to-bundle>`
- MUST generate an error if bundle path or container ID is missing.
- If `id` is not unique across all containers within the scope of the runtime, MUST generate an error; no new container MUST be created.
- MUST apply **all** properties from `config.json` **except** `process.args`.
  - `process.args` MUST NOT be applied until `start` is called.
  - The remaining `process` properties MAY be applied at create time.
- If a property cannot be applied as specified, MUST generate an error and no container MUST be created.
- Any changes to `config.json` after this operation MUST NOT affect the container.
- Runtime MAY validate `config.json` before creating (generic or system-specific).

#### `start <container-id>`
- MUST generate an error if container ID is missing.
- Attempting to `start` a container that is **not** in `created` state MUST have no effect and MUST generate an error.
- MUST run the user-specified program as specified by `process`.
- MUST generate an error if `process` was not set.

#### `kill <container-id> <signal>`
- MUST generate an error if container ID is missing.
- Sending a signal to a container that is **neither** `created` nor `running` MUST have no effect and MUST generate an error.
- MUST send the specified signal to the container process.

#### `delete <container-id>`
- MUST generate an error if container ID is missing.
- Attempting to `delete` a container that is **not** `stopped` MUST have no effect and MUST generate an error. (i.e. you cannot delete a running container — kill it first.)
- MUST delete resources created during the `create` step.
- Resources associated with the container but NOT created by this container MUST NOT be deleted.
- Once deleted, the container ID MAY be reused.

#### Idempotency
- The spec does not guarantee idempotency for any operation. Each of `start`, `kill`, `delete` explicitly MUST generate an error if the container is in the wrong state, meaning they are **not** idempotent in general.

---

## 2. The Bundle

> **Source:** [`opencontainers/runtime-spec:bundle.md`](https://github.com/opencontainers/runtime-spec/blob/main/bundle.md)

A **filesystem bundle** is a directory on the local filesystem containing:

1. **`config.json`** — REQUIRED. MUST reside in the **root** of the bundle directory and MUST be named exactly `config.json`.
2. **The container's root filesystem** — the directory referenced by `root.path` in `config.json`, if that property is set.

The directory containing these artifacts is **not itself part of the bundle** (a tar of a bundle has these artifacts at the archive root, not in a subdirectory).

> **Source:** [`config.md` — "Root"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#root)

### `root.path` semantics
- REQUIRED on all POSIX platforms.
- Either an **absolute path** or a **relative path to the bundle directory**.
  - e.g., bundle at `/to/bundle`, rootfs at `/to/bundle/rootfs` → `path` can be `/to/bundle/rootfs` **or** `rootfs`.
  - The value SHOULD be the conventional `rootfs`.
- A directory MUST exist at the path declared by this field.
- `readonly` (bool, OPTIONAL): if `true`, the root filesystem MUST be mounted read-only inside the container. Defaults to `false`.

---

## 3. Full `config.json` Schema for Linux Containers

> **Primary sources:** [`config.md`](https://github.com/opencontainers/runtime-spec/blob/main/config.md), [`config-linux.md`](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md)  
> **Schemas:** [`schema/config-schema.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/config-schema.json), [`schema/config-linux.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/config-linux.json), [`schema/defs.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/defs.json), [`schema/defs-linux.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/defs-linux.json)

**Top-level required field:** `ociVersion` (string, REQUIRED, semver 2.0.0).

---

### 3.1 `process`

> **Source:** [`config.md` — "Process"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#process)

`process` (object, OPTIONAL at `create` time, but REQUIRED when `start` is called).

| Field | Type | Req | Notes |
|---|---|---|---|
| `terminal` | bool | OPT | If `true`, allocate a pseudoterminal; pty duplicated on stdio. Defaults `false`. |
| `consoleSize` | object | OPT | `{height: uint, width: uint}`. Runtime MUST ignore if `terminal` is false/unset. |
| `cwd` | string | **REQ** | Absolute path. Working directory for the executable. |
| `env` | []string | OPT | `KEY=value` strings per IEEE 1003.1-2008 `environ`. |
| `args` | []string | OPT* | At least one entry REQUIRED on non-Windows; first entry used as `execvp`'s `file`. MUST NOT be applied until `start`. |

#### `process.user` (POSIX)
| Field | Type | Req | Notes |
|---|---|---|---|
| `uid` | uint32 | **REQ** | User ID in **container namespace** |
| `gid` | uint32 | **REQ** | Group ID in **container namespace** |
| `umask` | uint32 | OPT | If unspecified, calling process's umask is unchanged |
| `additionalGids` | []uint32 | OPT | Additional group IDs in container namespace |

#### `process.capabilities` (Linux)
> **Source:** [`config.md` — "Linux Process"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#linux-process)

All five sets are `[]string` of `CAP_*` names (e.g., `CAP_CHOWN`). All are OPTIONAL.

| Field | Semantics |
|---|---|
| `bounding` | Bounding set — caps that can ever be in permitted set |
| `effective` | Currently active capabilities |
| `inheritable` | Preserved across `execve` |
| `permitted` | Superset of effective, caps that may be set effective |
| `ambient` | Inherited across non-privileged `execve` (Linux 4.3+) |

**MUST:** Any value that cannot be mapped to a relevant kernel interface MUST be **logged as a warning** (not an error). Runtimes SHOULD NOT fail if capabilities cannot be granted (e.g., restricted environment).

#### `process.rlimits` (POSIX)
Array of `{type: string, soft: uint64, hard: uint64}`. `type` matches `RLIMIT_*` constants (e.g., `RLIMIT_NOFILE`). Duplicate `type` entries MUST generate an error. `rlim.rlim_cur` MUST match `soft`, `rlim.rlim_max` MUST match `hard`.

#### `process` — Linux-only fields

| Field | Type | Req | Notes |
|---|---|---|---|
| `noNewPrivileges` | bool | OPT | Sets `PR_SET_NO_NEW_PRIVS` via `prctl`. Prevents gaining privileges. |
| `apparmorProfile` | string | OPT | AppArmor profile name for the process |
| `selinuxLabel` | string | OPT | SELinux label for the process |
| `oomScoreAdj` | int | OPT | If set, runtime MUST set `/proc/[pid]/oom_score_adj`. If unset, MUST NOT change it. |
| `scheduler` | object | OPT | See below |
| `ioPriority` | object | OPT | `{class: string (REQUIRED), priority: int (REQUIRED)}`. `class` ∈ `{IOPRIO_CLASS_RT, IOPRIO_CLASS_BE, IOPRIO_CLASS_IDLE}`. `priority` 0 (highest) to 7 (lowest). Applies to the process group. |
| `execCPUAffinity` | object | OPT | `{initial: string, final: string}` — CPU affinity as comma-separated ranges (e.g., `"0-3,7"`). `initial` = before cgroup transition; `final` = after. Not applicable to container init process. |

#### `process.scheduler` (Linux)
```
policy     string  REQUIRED  One of: SCHED_OTHER, SCHED_FIFO, SCHED_RR,
                             SCHED_BATCH, SCHED_ISO, SCHED_IDLE, SCHED_DEADLINE
nice       int32   OPTIONAL  Default 0 if unset
priority   int32   OPTIONAL  Default 0 if unset (real-time policies)
flags      []string OPTIONAL SCHED_FLAG_RESET_ON_FORK, SCHED_FLAG_RECLAIM,
                             SCHED_FLAG_DL_OVERRUN, SCHED_FLAG_KEEP_POLICY,
                             SCHED_FLAG_KEEP_PARAMS, SCHED_FLAG_UTIL_CLAMP_MIN,
                             SCHED_FLAG_UTIL_CLAMP_MAX
runtime    uint64  OPTIONAL  Nanoseconds allowed per period (SCHED_DEADLINE). Default 0.
deadline   uint64  OPTIONAL  Absolute deadline in nanoseconds (SCHED_DEADLINE). Default 0.
period     uint64  OPTIONAL  Period in nanoseconds (SCHED_DEADLINE). Default 0.
```

---

### 3.2 `root`
> **Source:** [`config.md` — "Root"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#root)

```
root.path      string  REQUIRED  Abs or relative-to-bundle path; dir MUST exist
root.readonly  bool    OPTIONAL  If true, rootfs MUST be mounted read-only. Default false.
```

---

### 3.3 `hostname` and `domainname`
> **Source:** [`config.md` — "Hostname"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#hostname), ["Domainname"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#domainname)

```
hostname    string  OPTIONAL  Sets hostname in container UTS namespace
domainname  string  OPTIONAL  Sets domainname in container UTS namespace
```
Both depend on namespace config — if no UTS namespace is created, they set the runtime's UTS namespace.

---

### 3.4 `mounts`
> **Source:** [`config.md` — "Mounts"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#mounts)

Array of mount objects. The runtime MUST mount entries **in the listed order**.

| Field | Type | Req | Notes |
|---|---|---|---|
| `destination` | string | **REQ** | Absolute path inside container. Relative paths DEPRECATED (treated as relative to `/`). |
| `source` | string | OPT | Device or file/dir for bind mounts. Paths are absolute or relative to bundle. |
| `type` | string | OPT (POSIX) | Filesystem type (e.g., `proc`, `tmpfs`, `none` for bind). |
| `options` | []string | OPT | Mount options (see mount options table below) |
| `uidMappings` | []IDMapping | OPT (POSIX) | Per-mount UID mappings. MUST be specified with `gidMappings`. Use `mount_setattr(MOUNT_ATTR_IDMAP)`. |
| `gidMappings` | []IDMapping | OPT (POSIX) | Per-mount GID mappings. MUST be specified with `uidMappings`. |

#### Key Linux Mount Options (requirement level)

| Option | Level | Notes |
|---|---|---|
| `bind` / `rbind` | MUST | Bind / recursive bind mount |
| `ro` / `rw` | MUST | Read-only / read-write |
| `private`/`shared`/`slave`/`unbindable` | MUST | Propagation |
| `rprivate`/`rshared`/`rslave`/`runbindable` | MUST | Recursive propagation |
| `nodev`/`dev` | MUST | Device access |
| `noexec`/`exec` | MUST | Exec permission |
| `nosuid`/`suid` | MUST | setuid/setgid bits |
| `noatime`/`atime`/`relatime`/`strictatime` | MUST | Atime semantics |
| `remount`, `sync`, `async`, `defaults` | MUST | Standard options |
| `nosymfollow` | SHOULD | Kernel 5.10+ |
| `idmap` / `ridmap` | SHOULD | ID-mapped mount via `mount_setattr`; Linux 5.12+ |
| `ratime`,`rdev`,`rexec`,`rnoatime`, etc. | SHOULD | Recursive `AT_RECURSIVE` variants; Linux 5.12+ |
| `tmpcopyup` | MAY | Copy contents to tmpfs |
| `mand`/`nomand` | MAY | Deprecated in kernel 5.15 |

Runtimes SHOULD treat **unknown options as filesystem-specific** and pass them as a comma-separated string to `mount(2)`'s `data` argument.

---

### 3.5 `linux` — Namespaces

> **Source:** [`config-linux.md` — "Namespaces"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#namespaces)

`linux.namespaces` (array of objects, OPTIONAL):

```
type  string  REQUIRED  One of: pid, network, mount, ipc, uts, user, cgroup, time
path  string  OPTIONAL  Absolute path in runtime mount namespace to existing namespace fd
```

- If `path` is specified: runtime MUST place container process in that namespace. Runtime MUST generate an error if the path is not associated with the specified `type`.
- If `path` is absent: runtime MUST create a **new** container namespace of that type.
- If a type is **not listed**: container inherits the **runtime namespace** of that type.
- Duplicate `type` entries MUST generate an error.

---

### 3.6 `linux.uidMappings` / `linux.gidMappings`

> **Source:** [`config-linux.md` — "User Namespace Mappings"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#user-namespace-mappings)

Arrays of ID mapping objects. Each entry:
```
containerID  uint32  REQUIRED  Starting UID/GID in container
hostID       uint32  REQUIRED  Starting UID/GID on host to map to containerID
size         uint32  REQUIRED  Number of IDs to map
```
Runtime SHOULD NOT modify ownership of referenced filesystems to realize the mapping. Kernel may limit the number of mapping entries.

---

### 3.7 `linux.timeOffsets`

> **Source:** [`config-linux.md` — "Offset for Time Namespace"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#offset-for-time-namespace)

```
linux.timeOffsets  object  OPTIONAL  Sets offset for time namespace clocks
```
Keys are clock names (`boottime`, `monotonic`). Values:
```
secs      int64   OPTIONAL  Offset in seconds
nanosecs  uint32  OPTIONAL  Offset in nanoseconds
```

---

### 3.8 `linux.devices`

> **Source:** [`config-linux.md` — "Devices"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#devices)

Array of device objects that MUST be available in the container. Runtime MAY supply them via `mknod`, bind-mount, or symlink.

```
type      string  REQUIRED          c (char), b (block), u (unbuffered char), p (fifo)
path      string  REQUIRED          Full path inside container; MUST NOT conflict with existing file
major     int64   REQUIRED (not p)  Major device number
minor     int64   REQUIRED (not p)  Minor device number
fileMode  uint32  OPTIONAL          File permissions (decimal, not octal)
uid       uint32  OPTIONAL          Owner UID in container namespace
gid       uint32  OPTIONAL          Owner GID in container namespace
```

If a file already exists at `path` that does not match the requested device, the runtime MUST generate an error.

#### Default Devices (always provided by runtime)
`/dev/null`, `/dev/zero`, `/dev/full`, `/dev/random`, `/dev/urandom`, `/dev/tty`, `/dev/console` (if `terminal` enabled), `/dev/ptmx` (bind-mount/symlink to `/dev/pts/ptmx`).

---

### 3.9 `linux.cgroupsPath`

> **Source:** [`config-linux.md` — "Cgroups Path"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#cgroups-path)

```
linux.cgroupsPath  string  OPTIONAL
```
- If **absolute** (starts with `/`): relative to the cgroups mount point.
- If **relative**: MAY be interpreted relative to a runtime-determined location in the cgroups hierarchy.
- If specified, runtime MUST consistently attach to the same cgroup location for the same value.
- Cgroups will be created if they don't exist.
- Runtime MAY check if container cgroup is fit for purpose (e.g., not frozen, empty on create) and MUST generate an error if not.

---

### 3.10 `linux.resources`

> **Source:** [`config-linux.md` — "Control groups"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#control-groups)

#### `linux.resources.memory`

| Field | Type | Notes |
|---|---|---|
| `limit` | int64 | Memory limit in bytes; `-1` for unlimited |
| `reservation` | int64 | Soft limit in bytes |
| `swap` | int64 | Memory+Swap limit; `-1` for unlimited |
| `kernel` | int64 | Hard limit for kernel memory (NOT RECOMMENDED) |
| `kernelTCP` | int64 | Hard limit for kernel TCP buffer memory (NOT RECOMMENDED) |
| `swappiness` | uint64 | 0–100; higher = more swappy |
| `disableOOMKiller` | bool | `true` = OOM killer disabled; tasks killed immediately if `false` |
| `useHierarchy` | bool | `true` = child cgroups share limits |
| `checkBeforeUpdate` | bool | `true` = reject new limit if lower than current usage (cgroup v2 mimics v1) |

#### `linux.resources.cpu`

| Field | Type | Notes |
|---|---|---|
| `shares` | uint64 | Relative CPU time share |
| `quota` | int64 | Microseconds in one `period` all tasks may run; MUST NOT be smaller than `burst` |
| `burst` | uint64 | Maximum accumulated additional time (burst); MUST NOT exceed `quota` |
| `period` | uint64 | Period in microseconds (CFS scheduler) |
| `realtimeRuntime` | int64 | Microseconds for longest continuous RT access |
| `realtimePeriod` | uint64 | RT scheduler period |
| `cpus` | string | CPUs to run on (e.g., `"0-3,7"`) |
| `mems` | string | Memory nodes to run on |
| `idle` | int64 | `0` = default; `1` = SCHED_IDLE |

#### `linux.resources.pids`

```
limit  int64  OPTIONAL  Max tasks in cgroup; -1 = unlimited (max). 0 is valid and treated as such.
```

#### `linux.resources.blockIO`

| Field | Type | Notes |
|---|---|---|
| `weight` | uint16 | Per-cgroup weight (all devices) |
| `leafWeight` | uint16 | Weight competing with child cgroups |
| `weightDevice` | []object | Per-device: `major`, `minor`, `weight`, `leafWeight` (at least one of weight/leafWeight required per entry) |
| `throttleReadBpsDevice` | []object | `major`, `minor`, `rate` (bytes/sec) |
| `throttleWriteBpsDevice` | []object | Same |
| `throttleReadIOPSDevice` | []object | `major`, `minor`, `rate` (IOPS) |
| `throttleWriteIOPSDevice` | []object | Same |

Note: cgroup v1 I/O throttle applies only to Direct I/O; cgroup v2 does not have this limitation.

#### `linux.resources.hugepageLimits`

Array of `{pageSize: string, limit: uint64}`. `pageSize` format: `<size><unit-prefix>B` (e.g., `"2MB"`, `"64KB"`). `limit` in bytes.

#### `linux.resources.network`

```
classID    uint32    OPTIONAL  net_cls network class ID
priorities []object  OPTIONAL  [{name: string (interface in runtime ns), priority: uint32}]
```

#### `linux.resources.rdma`

Object keyed by device name (e.g., `"mlx5_1"`). Values:
```
hcaHandles  uint32  OPTIONAL  Max HCA handles
hcaObjects  uint32  OPTIONAL  Max HCA objects
```
At least one of `hcaHandles` or `hcaObjects` MUST be specified per entry.

#### `linux.resources.unified` (cgroup v2)

Object of `{string: string}` where keys are cgroup unified hierarchy filenames. OCI runtime MUST ensure needed cgroup controllers are enabled. Unknown configuration (to the runtime) MUST still be written to the relevant file. Runtime MUST generate an error if a referenced controller is absent/cannot be enabled.

#### `linux.resources.devices` (device allowlist)

Array of device cgroup allowlist entries; runtime MUST apply in **listed order**:
```
allow   bool    REQUIRED  Allow (true) or deny (false)
type    string  OPTIONAL  a=all, c=char, b=block. Unset = "all"
major   int64   OPTIONAL  Unset = all
minor   int64   OPTIONAL  Unset = all
access  string  OPTIONAL  Combination of r, w, m
```

---

### 3.11 `linux.seccomp`

> **Source:** [`config-linux.md` — "Seccomp"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#seccomp)

```
defaultAction    string    REQUIRED  Default action for all syscalls
defaultErrnoRet  uint32    OPTIONAL  errno for SCMP_ACT_ERRNO/SCMP_ACT_TRACE. Default: EPERM
architectures    []string  OPTIONAL  Seccomp architectures (SCMP_ARCH_*)
flags            []string  OPTIONAL  Seccomp filter flags
listenerPath     string    OPTIONAL  Unix socket path for SCMP_ACT_NOTIFY (AF_UNIX, SOCK_STREAM)
listenerMetadata string    OPTIONAL  Opaque metadata for seccomp agent (only valid with listenerPath)
syscalls         []Syscall OPTIONAL  Per-syscall rules
```

**`defaultAction`** and **`syscalls[].action`** valid values:
```
SCMP_ACT_KILL          Kill the calling thread
SCMP_ACT_KILL_PROCESS  Kill the entire process
SCMP_ACT_KILL_THREAD   Kill the calling thread (same as KILL)
SCMP_ACT_TRAP          Send SIGSYS
SCMP_ACT_ERRNO         Return errno (use errnoRet)
SCMP_ACT_TRACE         Notify tracer
SCMP_ACT_ALLOW         Allow
SCMP_ACT_LOG           Log and allow
SCMP_ACT_NOTIFY        Notify user-space agent (use listenerPath)
```

**`architectures`** (as of libseccomp v2.6.0): `SCMP_ARCH_X86`, `SCMP_ARCH_X86_64`, `SCMP_ARCH_X32`, `SCMP_ARCH_ARM`, `SCMP_ARCH_AARCH64`, `SCMP_ARCH_MIPS`, `SCMP_ARCH_MIPS64`, `SCMP_ARCH_MIPS64N32`, `SCMP_ARCH_MIPSEL`, `SCMP_ARCH_MIPSEL64`, `SCMP_ARCH_MIPSEL64N32`, `SCMP_ARCH_PPC`, `SCMP_ARCH_PPC64`, `SCMP_ARCH_PPC64LE`, `SCMP_ARCH_S390`, `SCMP_ARCH_S390X`, `SCMP_ARCH_PARISC`, `SCMP_ARCH_PARISC64`, `SCMP_ARCH_RISCV64`, `SCMP_ARCH_LOONGARCH64`, `SCMP_ARCH_M68K`, `SCMP_ARCH_SH`, `SCMP_ARCH_SHEB`

**`flags`**: `SECCOMP_FILTER_FLAG_TSYNC`, `SECCOMP_FILTER_FLAG_LOG`, `SECCOMP_FILTER_FLAG_SPEC_ALLOW`, `SECCOMP_FILTER_FLAG_WAIT_KILLABLE_RECV`

**`syscalls[]` object:**
```
names     []string  REQUIRED  Syscall names; must have ≥1 entry
action    string    REQUIRED  One of the SCMP_ACT_* values
errnoRet  uint32    OPTIONAL  errno override. Default EPERM. Error if action doesn't support it.
args      []SyscallArg  OPTIONAL  Argument filters
```

**`SyscallArg` object:**
```
index     uint32  REQUIRED  Syscall argument index (0-based)
value     uint64  REQUIRED  Value to compare
valueTwo  uint64  OPTIONAL  Second value (for SCMP_CMP_MASKED_EQ)
op        string  REQUIRED  One of: SCMP_CMP_NE, SCMP_CMP_LT, SCMP_CMP_LE,
                            SCMP_CMP_EQ, SCMP_CMP_GE, SCMP_CMP_GT, SCMP_CMP_MASKED_EQ
```

**For `SCMP_ACT_NOTIFY`:** Runtime MUST send exactly one `ContainerProcessState` per connection over `listenerPath` socket. Connection MUST NOT be reused. MUST close after sending. Runtime MUST send the `seccompFd` file descriptor via `SCM_RIGHTS`.

---

### 3.12 `linux.rootfsPropagation`

> **Source:** [`config-linux.md` — "Rootfs Mount Propagation"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#rootfs-mount-propagation)

```
linux.rootfsPropagation  string  OPTIONAL  One of: shared, slave, private, unbindable
```

- `shared`: rootfs belongs to a new peer group (nested mounts propagate back).
- `slave`: receives propagation events from host; not vice versa.
- `private`: no propagation from host; nested containers fully isolated.
- `unbindable`: private mount that cannot be bind-mounted.

---

### 3.13 `linux.maskedPaths`

> **Source:** [`config-linux.md` — "Masked Paths"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#masked-paths)

```
linux.maskedPaths  []string  OPTIONAL  Absolute paths in container namespace; made unreadable
```
Example: `["/proc/kcore"]`

---

### 3.14 `linux.readonlyPaths`

> **Source:** [`config-linux.md` — "Readonly Paths"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#readonly-paths)

```
linux.readonlyPaths  []string  OPTIONAL  Absolute paths in container namespace; set read-only
```
Example: `["/proc/sys"]`

---

### 3.15 `linux.mountLabel`

> **Source:** [`config-linux.md` — "Mount Label"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#mount-label)

```
linux.mountLabel  string  OPTIONAL  SELinux context for container mounts
```
Example: `"system_u:object_r:svirt_sandbox_file_t:s0:c715,c811"`

---

### 3.16 `linux.sysctl`

> **Source:** [`config-linux.md` — "Sysctl"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#sysctl)

```
linux.sysctl  {string: string}  OPTIONAL  Kernel parameters to modify at runtime
```
Example: `{"net.ipv4.ip_forward": "1", "net.core.somaxconn": "256"}`

---

### 3.17 `linux.intelRdt`

> **Source:** [`config-linux.md` — "IntelRdt"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#intel-rdt)

```
closID           string    OPTIONAL  RDT CLOS identity. "/" = default CLOS (resctrl root)
l3CacheSchema    string    OPTIONAL  L3 cache CBM schema (should start with "L3:")
memBwSchema      string    OPTIONAL  Memory bandwidth schema (MUST start with "MB:", no newlines)
schemata         []string  OPTIONAL  Lines to write to schemata file (no newlines)
enableMonitoring bool      OPTIONAL  Create dedicated MON group for container
```

**Rules:**
- Runtime MUST write container PID to `tasks` file in sub-directory under mounted `resctrl`. If no `resctrl` mounted, MUST generate an error.
- If `closID` unset: runtime MUST use container ID as directory name; MUST remove directory on container delete.
- If `closID` set and schema provided: create directory if absent; if present, MUST compare schema with existing schemata file and generate error on mismatch.
- `l3CacheSchema` written first, then `memBwSchema`, then `schemata`.
- If `enableMonitoring` set: MUST create `mon_groups/<container-id>/` subdirectory; MUST delete on container delete; MUST return error if creation fails.

---

### 3.18 `linux.personality`

> **Source:** [`config-linux.md` — "Personality"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#personality)

```
domain  string    REQUIRED  LINUX or LINUX32 (LINUX32 shows 32-bit CPU in uname)
flags   []string  OPTIONAL  Currently no flag values supported
```

---

### 3.19 `linux.memoryPolicy`

> **Source:** [`config-linux.md` — "Memory Policy"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#memory-policy)

```
mode   string    REQUIRED  MPOL_DEFAULT, MPOL_BIND, MPOL_INTERLEAVE,
                           MPOL_WEIGHTED_INTERLEAVE, MPOL_PREFERRED,
                           MPOL_PREFERRED_MANY, MPOL_LOCAL
nodes  string    OPTIONAL  Comma-separated NUMA node list (e.g., "0-3,7")
flags  []string  OPTIONAL  MPOL_F_NUMA_BALANCING, MPOL_F_RELATIVE_NODES,
                           MPOL_F_STATIC_NODES
```
Implemented via `set_mempolicy(2)`.

---

### 3.20 `linux.netDevices`

> **Source:** [`config-linux.md` — "Network Devices"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#network-devices)

Object keyed by host interface name. Values:
```
name  string  OPTIONAL  Name of interface inside container. If unset, host name is used.
```

- Runtime MUST move the device from host network namespace to container network namespace.
- Runtime MUST check if moving is possible; if interface with specified name already exists in container namespace, MUST generate error (unless new name has `%d` template, which lets the kernel generate a unique name).
- Runtime MUST preserve permanent IP addresses (IFA_F_PERMANENT, RT_SCOPE_UNIVERSE) when moving.
- Runtime MUST set device state to "up" after moving.
- Runtime MUST NOT attempt to move the interface back out before deletion.

---

### 3.21 Default Filesystems

> **Source:** [`config-linux.md` — "Default Filesystems"](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md#default-filesystems)

The following SHOULD be made available in each container:

| Path | Type |
|---|---|
| `/proc` | `proc` |
| `/sys` | `sysfs` |
| `/dev/pts` | `devpts` |
| `/dev/shm` | `tmpfs` |

---

## 4. POSIX Hooks

> **Source:** [`config.md` — "POSIX-platform Hooks"](https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks)

Each hook object: `{path: string (REQUIRED, absolute), args: []string (OPT), env: []string (OPT), timeout: int (OPT, >0 seconds)}`.

The container **state MUST be passed to hooks over stdin**.

Hooks MUST be called **in the listed order**.

### Hook Summary Table

| Name | Namespace | When (relative to create/start) | Deprecated? |
|---|---|---|---|
| `prestart` | **runtime** | During `create`, after runtime env created, before `pivot_root`. MUST be called before `createRuntime` hooks. | **YES** |
| `createRuntime` | **runtime** | During `create`, after runtime env created (mount namespace set up, mounts performed), before `pivot_root`. | No |
| `createContainer` | **container** | During `create`, after `createRuntime` hooks, same timing relative to `pivot_root`. | No |
| `startContainer` | **container** | After `start` is invoked, **before** user-specified program executes. | No |
| `poststart` | **runtime** | After user-specified process executes, before `start` operation returns. | No |
| `poststop` | **runtime** | After container is deleted, before `delete` operation returns. | No |

### Critical Namespace Details

> **Source:** [`config.md` — individual hook sections](https://github.com/opencontainers/runtime-spec/blob/main/config.md#posix-platform-hooks)

- **`prestart`**, **`createRuntime`**, **`poststart`**, **`poststop`**: path MUST resolve in the **runtime namespace**; hooks MUST execute in the **runtime namespace**.
- **`createContainer`**: path MUST resolve in the **runtime namespace**; hooks MUST execute in the **container namespace**.
- **`startContainer`**: path MUST resolve in the **container namespace**; hooks MUST execute in the **container namespace**.

### Hook Failure Semantics

> **Source:** [`runtime.md` — "Lifecycle"](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#lifecycle)

| Hook | Failure Result |
|---|---|
| `prestart` | MUST generate error, stop container, continue lifecycle at step 12 (destroy) |
| `createRuntime` | Same |
| `createContainer` | Same |
| `startContainer` | Same |
| `poststart` | MUST generate error, stop container, continue lifecycle at step 12 |
| `poststop` | MUST **log a warning** only; remaining hooks and lifecycle continue as normal |

### What `createRuntime` Guarantees
The spec explicitly notes that `createRuntime` hooks should only expect: the mount namespace has been created and mount operations performed. Cgroups and SELinux/AppArmor labels might not yet be set.

### What `createContainer` Guarantees
Hooks should only expect that the mount namespace and mounts are set up. Cgroups and SELinux/AppArmor labels might not yet be set. `pivot_root` has NOT yet executed.

---

## 5. Required Order of Operations: `create` → `start`

> **Source:** [`runtime.md` — "Lifecycle"](https://github.com/opencontainers/runtime-spec/blob/main/runtime.md#lifecycle)

The spec defines a **13-step lifecycle**. Steps 1–5 occur during `create`; steps 6–9 during `start`; steps 10–13 occur on exit+delete:

```
Step  Operation       Who/What
────────────────────────────────────────────────────────────────────────
1     create called   OCI runtime receives (container-id, bundle-path)
2     Create env      Runtime creates environment per config.json.
                      All properties EXCEPT process.args MUST be applied.
                      process.args MUST NOT run yet.
                      Errors here: MUST generate error; no container created.
3     prestart hooks  MUST be invoked (DEPRECATED; run in runtime namespace)
4     createRuntime   MUST be invoked (run in runtime namespace)
5     createContainer MUST be invoked (run in container namespace)
6     start called    Runtime receives (container-id)
7     startContainer  MUST be invoked (run in container namespace)
8     exec process    Runtime MUST run user-specified process (process.args)
9     poststart hooks MUST be invoked (run in runtime namespace)
10    process exits   Via error/exit/crash/kill
11    delete called   Runtime receives (container-id)
12    Destroy         Container MUST be destroyed (undo step 2 resources)
13    poststop hooks  MUST be invoked (run in runtime namespace)
```

### Linux-Specific create Ordering

> **Source:** [`config-linux.md`](https://github.com/opencontainers/runtime-spec/blob/main/config-linux.md) (synthesized from spec requirements)

Within step 2 (create environment), the canonical implementation order required by the spec's interdependencies is:

1. **Create/join namespaces** (`linux.namespaces`) — new namespaces or join existing via `path`. Must happen first so subsequent operations are in the correct namespace context.
2. **User namespace mappings** (`linux.uidMappings` / `linux.gidMappings`) — set up UID/GID mappings for user namespace.
3. **Set up cgroup** (`linux.cgroupsPath`, `linux.resources`) — attach process to cgroup hierarchy; configure controllers.
4. **Set up mounts** (`mounts`) — perform mounts in order listed; must be inside mount namespace.
5. **Apply sysctl** (`linux.sysctl`) — write kernel parameters (must be inside namespaces for network/uts parameters to be scoped correctly).
6. **`createRuntime` hooks** — fired here, in runtime namespace (mounts done, no `pivot_root` yet).
7. **`createContainer` hooks** — fired in container namespace (mounts done, no `pivot_root` yet).
8. **`pivot_root` (or `chroot`)** — change root to `root.path`.
9. **Apply `rootfsPropagation`** — set mount propagation on rootfs.
10. **Create devices** (`linux.devices`) — create/bind-mount device nodes in container.
11. **Apply seccomp** (`linux.seccomp`) — install seccomp filter (after mounts/chroot so paths are stable).
12. **Apply capabilities** (`process.capabilities`) — set bounding/effective/inheritable/permitted/ambient.
13. **Apply `noNewPrivileges`** — call `prctl(PR_SET_NO_NEW_PRIVS)`.
14. **Apply LSM labels** (`apparmorProfile`, `selinuxLabel`, `mountLabel`) — set AppArmor/SELinux contexts.
15. **Apply masked paths** (`linux.maskedPaths`) — bind-mount `/dev/null` or tmpfs over paths.
16. **Apply readonly paths** (`linux.readonlyPaths`) — remount paths read-only.
17. **Make rootfs read-only** (`root.readonly`) — if `true`, remount rootfs read-only.
18. **Set user/group** (`process.user`) — `setuid`/`setgid`/`setgroups` to uid/gid/additionalGids.
19. **Set OOM score adj** (`process.oomScoreAdj`) — write to `/proc/[pid]/oom_score_adj`.
20. **Set IntelRdt** (`linux.intelRdt`) — write PID to `resctrl` tasks file.
21. **Set personality** (`linux.personality`) — call `personality(2)`.
22. **Set memory policy** (`linux.memoryPolicy`) — call `set_mempolicy(2)`.

**During `start` (steps 6–9):**
1. `startContainer` hooks (in container namespace, before exec).
2. `exec(process.args)` with the configured `cwd`, `env`, scheduler, affinity.
3. `poststart` hooks (in runtime namespace).

---

## 6. Features Structure (`runtime features`)

> **Sources:** [`features.md`](https://github.com/opencontainers/runtime-spec/blob/main/features.md), [`features-linux.md`](https://github.com/opencontainers/runtime-spec/blob/main/features-linux.md)  
> **Schema:** [`schema/features-schema.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/features-schema.json), [`schema/features-linux.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/features-linux.json)

The features structure is an OPTIONAL JSON document a runtime MAY expose (e.g., via `runtime features`). It describes what the runtime supports, determined **at compile time**, not execution time.

### Top-Level Fields

```
ociVersionMin  string    REQUIRED  Minimum config.json ociVersion the runtime accepts
ociVersionMax  string    REQUIRED  Maximum config.json ociVersion the runtime accepts.
                                   MUST NOT be less than ociVersionMin.
hooks          []string  OPTIONAL  Recognized hook names
mountOptions   []string  OPTIONAL  Recognized mount option strings
linux          object    OPTIONAL  Linux-specific features (see below)
annotations    object    OPTIONAL  Arbitrary runtime metadata (key-value map)
potentiallyUnsafeConfigAnnotations  []string  OPTIONAL
                                   config.json annotation keys that may change
                                   runtime behavior. Values ending in "." are prefixes.
```

All properties except `ociVersionMin` and `ociVersionMax` MAY be absent or `null`. `null` MUST NOT be confused with `0`, `false`, `""`, `[]`, `{}`.

### `linux` Features Sub-Object

> **Source:** [`features-linux.md`](https://github.com/opencontainers/runtime-spec/blob/main/features-linux.md)

```
namespaces    []string  OPTIONAL  Recognized namespace types (runtime MUST accept these
                                  as linux.namespaces[].type in config.json)
capabilities  []string  OPTIONAL  Recognized CAP_* names (runtime MUST accept in
                                  process.capabilities)
cgroup        object    OPTIONAL  {v1: bool, v2: bool, systemd: bool, systemdUser: bool,
                                   rdma: bool}
seccomp       object    OPTIONAL  {enabled: bool, actions: []string, operators: []string,
                                   archs: []string, knownFlags: []string, supportedFlags: []string}
apparmor      object    OPTIONAL  {enabled: bool}
selinux       object    OPTIONAL  {enabled: bool}
memoryPolicy  object    OPTIONAL  {modes: []string, flags: []string}
intelRdt      object    OPTIONAL  {enabled: bool, schemata: bool, monitoring: bool}
mountExtensions object  OPTIONAL  {idmap: {enabled: bool}}
netDevices    object    OPTIONAL  {enabled: bool}
```

**`knownFlags` vs `supportedFlags` (seccomp):** `knownFlags` = all flags the runtime recognizes (including those not supported on current kernel). `supportedFlags` = subset that is actually recognized AND supported. The runtime MUST recognize and support elements in `supportedFlags`.

### Example `runtime features` Output

```json
{
  "ociVersionMin": "1.0.0",
  "ociVersionMax": "1.1.0-rc.2",
  "hooks": ["prestart","createRuntime","createContainer","startContainer","poststart","poststop"],
  "linux": {
    "namespaces": ["cgroup","ipc","mount","network","pid","user","uts"],
    "cgroup": {"v1": true, "v2": true, "systemd": true, "systemdUser": true, "rdma": true},
    "seccomp": {
      "enabled": true,
      "actions": ["SCMP_ACT_ALLOW","SCMP_ACT_ERRNO","SCMP_ACT_KILL","SCMP_ACT_KILL_PROCESS",
                  "SCMP_ACT_KILL_THREAD","SCMP_ACT_LOG","SCMP_ACT_NOTIFY","SCMP_ACT_TRACE","SCMP_ACT_TRAP"],
      "operators": ["SCMP_CMP_EQ","SCMP_CMP_GE","SCMP_CMP_GT","SCMP_CMP_LE","SCMP_CMP_LT",
                    "SCMP_CMP_MASKED_EQ","SCMP_CMP_NE"],
      "knownFlags": ["SECCOMP_FILTER_FLAG_TSYNC","SECCOMP_FILTER_FLAG_SPEC_ALLOW","SECCOMP_FILTER_FLAG_LOG"],
      "supportedFlags": ["SECCOMP_FILTER_FLAG_TSYNC","SECCOMP_FILTER_FLAG_SPEC_ALLOW","SECCOMP_FILTER_FLAG_LOG"]
    },
    "apparmor": {"enabled": true},
    "selinux": {"enabled": true},
    "intelRdt": {"enabled": true, "schemata": true, "monitoring": true}
  }
}
```

---

## 7. Quick-Reference: MUST vs. SHOULD vs. MAY Summary

| Requirement | Level | Source |
|---|---|---|
| `ociVersion` in config.json | MUST | `config.md` |
| `root.path` directory exists | MUST | `config.md` |
| Mount entries applied in listed order | MUST | `config.md` |
| `process.args` NOT applied at create | MUST | `runtime.md` |
| Unique container ID across scope | MUST | `runtime.md` |
| Error if start called on non-created container | MUST | `runtime.md` |
| Error if delete called on non-stopped container | MUST | `runtime.md` |
| Duplicate rlimit type entries → error | MUST | `config.md` |
| Duplicate namespace type entries → error | MUST | `config-linux.md` |
| `cgroupsPath` absolute → relative to cgroups mount | MUST | `config-linux.md` |
| `linux.devices` path conflict → error | MUST | `config-linux.md` |
| `linux.resources.devices` applied in order | MUST | `config-linux.md` |
| `linux.intelRdt` → PID written to resctrl tasks | MUST | `config-linux.md` |
| `seccomp.defaultAction` REQUIRED | MUST | `config-linux.md` |
| `seccomp listenerPath` socket one conn per event | MUST | `config-linux.md` |
| Unknown config.json properties → ignore (log warning optional) | MUST ignore | `config.md` |
| Default devices `/dev/null` etc. | MUST supply | `config-linux.md` |
| `/proc`, `/sys`, `/dev/pts`, `/dev/shm` | SHOULD provide | `config-linux.md` |
| `process.capabilities` unmappable values → warning (not error) | SHOULD warn, SHOULD NOT fail | `config.md` |
| `root.path` = `rootfs` | SHOULD | `config.md` |
| `idmap` / `ridmap` via `mount_setattr` | SHOULD | `config.md` |
| `nosymfollow` option | SHOULD | `config.md` |
| UID/GID mappings don't modify filesystem ownership | SHOULD NOT | `config-linux.md` |
| Cgroup v1 ownership changes | SHOULD NOT | `config-linux.md` |
| Cgroup ownership change only with cgroup namespace | SHOULD NOT change unless cgroup NS created | `config-linux.md` |
| `poststop` hook failure → log warning only, continue | MUST warn, continue | `runtime.md` |
| Features structure determination at compile time | SHOULD | `features.md` |

---

## 8. Key Schema File Index

| File | Content |
|---|---|
| [`schema/config-schema.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/config-schema.json) | Root config.json JSON Schema (draft-04) |
| [`schema/config-linux.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/config-linux.json) | `linux` object definition |
| [`schema/defs.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/defs.json) | Shared type definitions (int types, Hook, Mount, IDMapping, etc.) |
| [`schema/defs-linux.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/defs-linux.json) | Linux type definitions (SeccompAction, SeccompArch, NamespaceType, Device, SchedulerPolicy, etc.) |
| [`schema/state-schema.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/state-schema.json) | Container state JSON Schema |
| [`schema/features-schema.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/features-schema.json) | Features structure JSON Schema |
| [`schema/features-linux.json`](https://github.com/opencontainers/runtime-spec/blob/main/schema/features-linux.json) | Linux features sub-object schema |

---

## Notes / Gaps

1. **`create` step 2 internal Linux ordering**: The spec describes *what* must happen (namespaces, mounts, devices, etc.) but does not prescribe an exact sequential order beyond the high-level lifecycle steps. The ordering in Section 5 above is synthesized from the interdependencies stated throughout the spec and matches the runc reference implementation's approach (the spec defers implementation ordering to the runtime).

2. **`createRuntime` / `createContainer` underspecification**: The spec explicitly acknowledges these are "currently underspecified." Only the mount namespace and mounts are guaranteed to be complete; cgroups and LSM labels *might not yet* be applied when these hooks fire.

3. **cgroup v1 vs v2 fieldsets**: Several `linux.resources` fields apply only to cgroup v1 (e.g., `kernel`, `kernelTCP`, `blkio` weight-device, `net_cls`/`net_prio`). For cgroup v2, use `linux.resources.unified` for direct controller file writes.

4. **`execCPUAffinity` not for init process**: The spec explicitly states `execCPUAffinity` is not applicable to the container's init process — only to processes invoked via `exec`.

5. **Seccomp `SCMP_ARCH_LOONGARCH64`, `SCMP_ARCH_M68K`, `SCMP_ARCH_SH`, `SCMP_ARCH_SHEB`, `SCMP_ARCH_PARISC`, `SCMP_ARCH_PARISC64`** are in the spec (config-linux.md) but are NOT in the schema (`defs-linux.json`). Verify against the exact spec version you target.