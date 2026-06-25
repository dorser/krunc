//! `krunc-oci` — translate the (untrusted) OCI `config.json` into a validated
//! [`krunc_abi::DomainSpec`].
//!
//! This is the userspace half of the boundary: complex parsing of untrusted
//! input lives here (never in the kernel). serde parses the bundle config; this
//! crate maps the supported subset onto the fixed, bounded ABI spec that the
//! kernel consumes. Everything here is safe Rust.
//!
//! Supported subset (others are ignored or rejected with [`OciError::Unsupported`]):
//! `process.args/env`, `process.noNewPrivileges`, `process.capabilities.bounding`,
//! `root.path/readonly`, `hostname`, `linux.namespaces`, `linux.uid/gidMappings`.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::HashMap;
use std::fmt;
use std::path::{Path, PathBuf};

use krunc_abi::{
    DomainSpec, IdMap, Mount, Rlimit, NS_CGROUP, NS_IPC, NS_MOUNT, NS_NET, NS_PID, NS_USER, NS_UTS,
    OPT_NO_NEW_PRIVS, OPT_ROOTFS_RO,
};
use serde::Deserialize;


/// The OCI runtime `config.json`, restricted to the fields krunc consumes.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct OciConfig {
    /// Spec version (informational).
    pub oci_version: Option<String>,
    /// Container hostname (UTS nodename).
    pub hostname: Option<String>,
    /// The container process.
    pub process: Option<Process>,
    /// The container root filesystem.
    pub root: Option<Root>,
    /// Linux-specific configuration.
    pub linux: Option<Linux>,
    /// Filesystem mounts to perform in the container.
    #[serde(default)]
    pub mounts: Vec<OciMount>,
    /// OCI annotations: free-form key/value metadata, not applied to the
    /// container itself. krunc reads `org.krunc.*` keys for runtime-specific
    /// opt-ins (e.g. `org.krunc.bpf-lsm` = `block`|`kill` to arm the per-container
    /// BPF-LSM escape-blocking policy).
    #[serde(default)]
    pub annotations: HashMap<String, String>,
    /// Any other top-level `config.json` properties krunc does not model. A
    /// non-whitelisted entry here is rejected (the runtime-spec requires the
    /// runtime to apply every configured property or error).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// A `config.json` top-level `mounts[]` entry.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct OciMount {
    /// Mountpoint inside the container.
    pub destination: String,
    /// Filesystem type (`proc`, `sysfs`, `tmpfs`, `bind`, …).
    #[serde(rename = "type", default)]
    pub mount_type: String,
    /// Source (device, fs name, or bind source).
    #[serde(default)]
    pub source: String,
    /// Mount options (`ro`, `nosuid`, `nodev`, `noexec`, `bind`, …).
    #[serde(default)]
    pub options: Vec<String>,
}

/// `config.json` `process`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    /// Allocate a terminal for the process.
    #[serde(default)]
    pub terminal: bool,
    /// argv; `args[0]` is the binary.
    #[serde(default)]
    pub args: Vec<String>,
    /// Environment, each `KEY=VALUE`.
    #[serde(default)]
    pub env: Vec<String>,
    /// Working directory inside the container.
    pub cwd: Option<String>,
    /// Target user.
    pub user: Option<User>,
    /// Capability sets.
    pub capabilities: Option<Capabilities>,
    /// Set `no_new_privs` before exec.
    #[serde(default)]
    pub no_new_privileges: bool,
    /// Resource limits to apply to the process.
    #[serde(default)]
    pub rlimits: Vec<OciRlimit>,
    /// Adjust the process OOM-killer score.
    pub oom_score_adj: Option<i32>,
    /// Other `process` properties krunc does not model (rejected if present).
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// `config.json` `process.rlimits[]`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OciRlimit {
    /// `RLIMIT_*` name, e.g. `RLIMIT_NOFILE`.
    #[serde(rename = "type")]
    pub limit_type: String,
    /// Soft limit.
    #[serde(default)]
    pub soft: u64,
    /// Hard limit.
    #[serde(default)]
    pub hard: u64,
}

/// `config.json` `process.user`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct User {
    /// Target uid.
    #[serde(default)]
    pub uid: u32,
    /// Target gid.
    #[serde(default)]
    pub gid: u32,
    /// Supplementary gids.
    #[serde(default)]
    pub additional_gids: Vec<u32>,
}

/// `config.json` `process.capabilities`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Capabilities {
    /// The bounding set (the ceiling krunc enforces).
    #[serde(default)]
    pub bounding: Vec<String>,
    /// Effective set.
    #[serde(default)]
    pub effective: Vec<String>,
    /// Permitted set.
    #[serde(default)]
    pub permitted: Vec<String>,
    /// Inheritable set.
    #[serde(default)]
    pub inheritable: Vec<String>,
    /// Ambient set.
    #[serde(default)]
    pub ambient: Vec<String>,
}

/// `config.json` `root`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Root {
    /// Rootfs path (relative to the bundle unless absolute).
    pub path: String,
    /// Mount the rootfs read-only.
    #[serde(default)]
    pub readonly: bool,
}

/// `config.json` `linux`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Linux {
    /// Namespaces to create or join.
    #[serde(default)]
    pub namespaces: Vec<Namespace>,
    /// uid mappings for a user namespace.
    #[serde(default)]
    pub uid_mappings: Vec<LinuxIdMapping>,
    /// gid mappings for a user namespace.
    #[serde(default)]
    pub gid_mappings: Vec<LinuxIdMapping>,
    /// cgroup resource limits.
    pub resources: Option<Resources>,
    /// cgroups path (relative to the cgroup mount).
    pub cgroups_path: Option<String>,
    /// Paths to make inaccessible inside the container.
    #[serde(default)]
    pub masked_paths: Vec<String>,
    /// Paths to remount read-only inside the container.
    #[serde(default)]
    pub readonly_paths: Vec<String>,
    /// Kernel sysctls to set in the container's namespaces (`name` -> `value`).
    #[serde(default)]
    pub sysctl: HashMap<String, String>,
    /// Other `linux` properties krunc does not model (rejected if present) —
    /// e.g. `devices`, `rootfsPropagation`, `intelRdt`, `seccomp`.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// `config.json` `linux.resources` (the subset krunc enforces via cgroup v2).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    /// pids controller.
    pub pids: Option<Pids>,
    /// memory controller.
    pub memory: Option<Memory>,
    /// cpu controller.
    pub cpu: Option<Cpu>,
    /// Other `resources` controllers krunc does not model (rejected if present)
    /// — e.g. `devices` (the device cgroup), `blockIO`, `hugepageLimits`.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// `config.json` `linux.resources.cpu` (the subset krunc enforces).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Cpu {
    /// CFS quota in microseconds per `period` (`<= 0` means unlimited).
    pub quota: Option<i64>,
    /// CFS period in microseconds (default 100000).
    pub period: Option<u64>,
    /// Relative CPU weight (OCI `shares`, 2..=262144).
    pub shares: Option<u64>,
}

/// `config.json` `linux.resources.pids`.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Pids {
    /// Maximum number of pids (`pids.max`).
    pub limit: i64,
}

/// `config.json` `linux.resources.memory` (the subset krunc enforces).
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Memory {
    /// Memory usage hard limit in bytes (`memory.max`). A negative value or
    /// `None` means unlimited.
    pub limit: Option<i64>,
}

/// Cgroup configuration extracted for the CLI to apply (userspace configures the
/// cgroup; the kernel enforces it).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CgroupConfig {
    /// Path relative to the cgroup-v2 mount (default `krunc/<id>` if absent).
    pub path: Option<String>,
    /// `pids.max`, if set.
    pub pids_limit: Option<i64>,
    /// `memory.max` in bytes, if set (and non-negative).
    pub memory_limit: Option<i64>,
    /// `cpu.max` value (`"<quota> <period>"`), if a positive quota is set.
    pub cpu_max: Option<String>,
    /// `cpu.weight` (1..=10000), mapped from OCI `shares`, if set.
    pub cpu_weight: Option<u64>,
}

/// Map an OCI cpu `shares` value (2..=262144) to a cgroup-v2 `cpu.weight`
/// (1..=10000), the same conversion runc/crun use.
fn shares_to_weight(shares: u64) -> u64 {
    if shares == 0 {
        return 0;
    }
    let w = 1 + ((shares.clamp(2, 262_144) - 2) * 9999) / 262_142;
    w.clamp(1, 10_000)
}

/// Extract the cgroup configuration from a parsed config.
pub fn cgroup_config(cfg: &OciConfig) -> CgroupConfig {
    let linux = cfg.linux.as_ref();
    let resources = linux.and_then(|l| l.resources.as_ref());
    let cpu = resources.and_then(|r| r.cpu.as_ref());
    let cpu_max = cpu.and_then(|c| match c.quota {
        Some(q) if q > 0 => Some(format!("{} {}", q, c.period.unwrap_or(100_000))),
        _ => None,
    });
    let cpu_weight = cpu
        .and_then(|c| c.shares)
        .filter(|&s| s != 0)
        .map(shares_to_weight);
    CgroupConfig {
        path: linux.and_then(|l| l.cgroups_path.clone()),
        pids_limit: resources.and_then(|r| r.pids.as_ref()).map(|p| p.limit),
        memory_limit: resources
            .and_then(|r| r.memory.as_ref())
            .and_then(|m| m.limit)
            .filter(|&l| l >= 0),
        cpu_max,
        cpu_weight,
    }
}

/// A `linux.namespaces` entry.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Namespace {
    /// Namespace type (`pid`, `mount`, `network`, `ipc`, `uts`, `user`, `cgroup`).
    #[serde(rename = "type")]
    pub ns_type: String,
    /// If set, join an existing namespace at this path (not yet supported).
    pub path: Option<String>,
}

/// A `linux.uidMappings`/`gidMappings` entry.
#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct LinuxIdMapping {
    /// First id inside the container.
    #[serde(rename = "containerID")]
    pub container_id: u32,
    /// First id on the host.
    #[serde(rename = "hostID")]
    pub host_id: u32,
    /// Number of ids mapped.
    pub size: u32,
}

/// Translation errors.
#[derive(Debug)]
pub enum OciError {
    /// `config.json` could not be parsed.
    Json(serde_json::Error),
    /// A required field was absent.
    Missing(&'static str),
    /// An unknown capability name.
    UnknownCapability(String),
    /// A field uses a feature krunc does not (yet) support.
    Unsupported(&'static str),
    /// A configured `config.json` property krunc cannot apply. Per the OCI
    /// runtime-spec (create: "if the runtime cannot apply a property as
    /// specified, it MUST generate an error"), krunc rejects rather than
    /// silently ignoring it.
    UnsupportedProperty(String),
    /// The translated spec violated an ABI bound.
    Abi(krunc_abi::AbiError),
}

impl fmt::Display for OciError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            OciError::Json(e) => write!(f, "parsing config.json: {e}"),
            OciError::Missing(s) => write!(f, "config.json: missing required field {s}"),
            OciError::UnknownCapability(c) => write!(f, "unknown capability {c}"),
            OciError::Unsupported(s) => write!(f, "unsupported config.json feature: {s}"),
            OciError::UnsupportedProperty(s) => {
                write!(f, "config.json sets {s}, which krunc cannot apply (the OCI runtime-spec requires the runtime to error rather than ignore it)")
            }
            OciError::Abi(e) => write!(f, "spec exceeds ABI limits: {e}"),
        }
    }
}

impl std::error::Error for OciError {}

impl From<serde_json::Error> for OciError {
    fn from(e: serde_json::Error) -> Self {
        OciError::Json(e)
    }
}
impl From<krunc_abi::AbiError> for OciError {
    fn from(e: krunc_abi::AbiError) -> Self {
        OciError::Abi(e)
    }
}

/// Parse a `config.json` document.
pub fn parse_config(json: &str) -> Result<OciConfig, OciError> {
    Ok(serde_json::from_str(json)?)
}

/// The BPF-LSM enforcement mode requested via the `org.krunc.bpf-lsm` annotation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfLsmMode {
    /// Deny escape attempts with `-EPERM`; the container keeps running.
    Block,
    /// Deny and additionally `SIGKILL` the container on an escape attempt.
    Kill,
}

impl BpfLsmMode {
    /// The `krunc-bpf guard` mode argument (`block`/`kill`).
    pub fn as_arg(self) -> &'static str {
        match self {
            BpfLsmMode::Block => "block",
            BpfLsmMode::Kill => "kill",
        }
    }
}

/// Read the optional per-container BPF-LSM opt-in from the config's annotations.
/// `org.krunc.bpf-lsm` = `block` | `kill` arms the escape-blocking policy; absent
/// (or any other value) means no BPF-LSM guarding. Returns an error for an
/// unrecognized value so a typo fails closed rather than silently disabling it.
pub fn bpf_lsm_mode(cfg: &OciConfig) -> Result<Option<BpfLsmMode>, OciError> {
    match cfg.annotations.get("org.krunc.bpf-lsm").map(String::as_str) {
        None => Ok(None),
        Some("block") => Ok(Some(BpfLsmMode::Block)),
        Some("kill") => Ok(Some(BpfLsmMode::Kill)),
        Some(other) => Err(OciError::UnsupportedProperty(format!(
            "annotation org.krunc.bpf-lsm={other:?} (expected block|kill)"
        ))),
    }
}

/// Resolve `root.path` against the bundle directory (absolute paths kept as-is).
fn resolve_rootfs(bundle: &Path, root_path: &str) -> String {
    let p = Path::new(root_path);
    let resolved: PathBuf = if p.is_absolute() {
        p.to_path_buf()
    } else {
        bundle.join(p)
    };
    resolved.to_string_lossy().into_owned()
}

/// Translate OCI `uid/gidMappings` into the ABI [`IdMap`] form. Each mapping must
/// cover at least one id (`size > 0`); an empty list yields no maps. The ABI
/// encoder bounds the count (`MAX_MAPS`).
fn translate_id_maps(maps: &[LinuxIdMapping]) -> Result<Vec<IdMap>, OciError> {
    let mut out = Vec::with_capacity(maps.len());
    for m in maps {
        if m.size == 0 {
            return Err(OciError::UnsupportedProperty(
                "uid/gidMappings entry with size 0".into(),
            ));
        }
        out.push(IdMap {
            container_id: m.container_id,
            host_id: m.host_id,
            size: m.size,
        });
    }
    Ok(out)
}

/// Map an OCI namespace type string to its `CLONE_NEW*` flag.
fn ns_flag(ns_type: &str) -> Result<u32, OciError> {
    Ok(match ns_type {
        "pid" => NS_PID,
        "mount" => NS_MOUNT,
        "network" => NS_NET,
        "ipc" => NS_IPC,
        "uts" => NS_UTS,
        "user" => NS_USER,
        "cgroup" => NS_CGROUP,
        "time" => return Err(OciError::Unsupported("time namespace")),
        _ => return Err(OciError::Unsupported("unknown namespace type")),
    })
}

/// The Linux capability name → bit-index table.
const CAPS: &[(&str, u8)] = &[
    ("CAP_CHOWN", 0),
    ("CAP_DAC_OVERRIDE", 1),
    ("CAP_DAC_READ_SEARCH", 2),
    ("CAP_FOWNER", 3),
    ("CAP_FSETID", 4),
    ("CAP_KILL", 5),
    ("CAP_SETGID", 6),
    ("CAP_SETUID", 7),
    ("CAP_SETPCAP", 8),
    ("CAP_LINUX_IMMUTABLE", 9),
    ("CAP_NET_BIND_SERVICE", 10),
    ("CAP_NET_BROADCAST", 11),
    ("CAP_NET_ADMIN", 12),
    ("CAP_NET_RAW", 13),
    ("CAP_IPC_LOCK", 14),
    ("CAP_IPC_OWNER", 15),
    ("CAP_SYS_MODULE", 16),
    ("CAP_SYS_RAWIO", 17),
    ("CAP_SYS_CHROOT", 18),
    ("CAP_SYS_PTRACE", 19),
    ("CAP_SYS_PACCT", 20),
    ("CAP_SYS_ADMIN", 21),
    ("CAP_SYS_BOOT", 22),
    ("CAP_SYS_NICE", 23),
    ("CAP_SYS_RESOURCE", 24),
    ("CAP_SYS_TIME", 25),
    ("CAP_SYS_TTY_CONFIG", 26),
    ("CAP_MKNOD", 27),
    ("CAP_LEASE", 28),
    ("CAP_AUDIT_WRITE", 29),
    ("CAP_AUDIT_CONTROL", 30),
    ("CAP_SETFCAP", 31),
    ("CAP_MAC_OVERRIDE", 32),
    ("CAP_MAC_ADMIN", 33),
    ("CAP_SYSLOG", 34),
    ("CAP_WAKE_ALARM", 35),
    ("CAP_BLOCK_SUSPEND", 36),
    ("CAP_AUDIT_READ", 37),
    ("CAP_PERFMON", 38),
    ("CAP_BPF", 39),
    ("CAP_CHECKPOINT_RESTORE", 40),
];

/// Convert a capability name to its bit index.
pub fn cap_bit(name: &str) -> Option<u8> {
    CAPS.iter().find(|(n, _)| *n == name).map(|(_, b)| *b)
}

/// Convert a list of capability names into a bitmask.
fn caps_to_mask(names: &[String]) -> Result<u64, OciError> {
    let mut mask = 0u64;
    for n in names {
        let bit = cap_bit(n).ok_or_else(|| OciError::UnknownCapability(n.clone()))?;
        mask |= 1u64 << bit;
    }
    Ok(mask)
}

/// Resolve an OCI `RLIMIT_*` name to its Linux resource number
/// (`include/uapi/asm-generic/resource.h`).
fn rlimit_resource(name: &str) -> Option<u32> {
    Some(match name {
        "RLIMIT_CPU" => 0,
        "RLIMIT_FSIZE" => 1,
        "RLIMIT_DATA" => 2,
        "RLIMIT_STACK" => 3,
        "RLIMIT_CORE" => 4,
        "RLIMIT_RSS" => 5,
        "RLIMIT_NPROC" => 6,
        "RLIMIT_NOFILE" => 7,
        "RLIMIT_MEMLOCK" => 8,
        "RLIMIT_AS" => 9,
        "RLIMIT_LOCKS" => 10,
        "RLIMIT_SIGPENDING" => 11,
        "RLIMIT_MSGQUEUE" => 12,
        "RLIMIT_NICE" => 13,
        "RLIMIT_RTPRIO" => 14,
        "RLIMIT_RTTIME" => 15,
        _ => return None,
    })
}

/// Translate validated OCI mount `options` into `(MS_* flags, is_bind)`. Options
/// are first screened by [`check_mount_options`], so the only non-flag string
/// reaching the catch-all here is `defaults` (a no-op denoting the default
/// flags); krunc applies no per-fs data string.
fn mount_flags(options: &[String]) -> (u64, bool) {
    // uapi/linux/mount.h bit values.
    const MS_RDONLY: u64 = 1;
    const MS_NOSUID: u64 = 2;
    const MS_NODEV: u64 = 4;
    const MS_NOEXEC: u64 = 8;
    const MS_SYNCHRONOUS: u64 = 16;
    const MS_REMOUNT: u64 = 32;
    const MS_DIRSYNC: u64 = 128;
    const MS_BIND: u64 = 4096;
    const MS_REC: u64 = 16384;
    const MS_SILENT: u64 = 32768;
    const MS_NOATIME: u64 = 1024;
    const MS_NODIRATIME: u64 = 2048;
    const MS_RELATIME: u64 = 1 << 21;
    const MS_I_VERSION: u64 = 1 << 23;
    const MS_STRICTATIME: u64 = 1 << 24;
    const MS_LAZYTIME: u64 = 1 << 25;

    let mut flags = 0u64;
    let mut is_bind = false;
    for opt in options {
        match opt.as_str() {
            "defaults" => {} // rw,suid,dev,exec,async,relatime — i.e. no special flags
            "ro" => flags |= MS_RDONLY,
            "rw" => flags &= !MS_RDONLY,
            "nosuid" => flags |= MS_NOSUID,
            "suid" => flags &= !MS_NOSUID,
            "nodev" => flags |= MS_NODEV,
            "dev" => flags &= !MS_NODEV,
            "noexec" => flags |= MS_NOEXEC,
            "exec" => flags &= !MS_NOEXEC,
            "sync" => flags |= MS_SYNCHRONOUS,
            "async" => flags &= !MS_SYNCHRONOUS,
            "dirsync" => flags |= MS_DIRSYNC,
            "remount" => flags |= MS_REMOUNT,
            "noatime" => flags |= MS_NOATIME,
            "atime" => flags &= !MS_NOATIME,
            "nodiratime" => flags |= MS_NODIRATIME,
            "diratime" => flags &= !MS_NODIRATIME,
            "relatime" => flags |= MS_RELATIME,
            "norelatime" => flags &= !MS_RELATIME,
            "strictatime" => flags |= MS_STRICTATIME,
            "nostrictatime" => flags &= !MS_STRICTATIME,
            "lazytime" => flags |= MS_LAZYTIME,
            "nolazytime" => flags &= !MS_LAZYTIME,
            "iversion" => flags |= MS_I_VERSION,
            "noiversion" => flags &= !MS_I_VERSION,
            "loud" => flags &= !MS_SILENT,
            "bind" => {
                flags |= MS_BIND;
                is_bind = true;
            }
            "rbind" => {
                flags |= MS_BIND | MS_REC;
                is_bind = true;
            }
            _ => {} // unreachable: check_mount_options screens unknown options first
        }
    }
    (flags, is_bind)
}

/// Reject mount `options` krunc cannot apply. krunc implements the flag-based
/// `MS_*` options the runtime-spec lists as MUST (see [`mount_flags`]).
/// Filesystem data options (`size=`, `mode=`, …) and the mount-propagation
/// options (`private`, `shared`, `slave`, `unbindable` and their recursive
/// forms — which require a separate `mount(2)` propagation call krunc does not
/// yet make) are rejected rather than silently dropped, per the create rule
/// ("a runtime MUST error on a property it cannot apply").
fn check_mount_options(options: &[String]) -> Result<(), OciError> {
    for opt in options {
        match opt.as_str() {
            "defaults" | "ro" | "rw" | "nosuid" | "suid" | "nodev" | "dev" | "noexec" | "exec"
            | "sync" | "async" | "dirsync" | "remount" | "noatime" | "atime" | "nodiratime"
            | "diratime" | "relatime" | "norelatime" | "strictatime" | "nostrictatime"
            | "lazytime" | "nolazytime" | "iversion" | "noiversion" | "loud" | "bind"
            | "rbind" => {}
            _ => {
                return Err(OciError::UnsupportedProperty(format!(
                    "mounts[].options: {opt}"
                )))
            }
        }
    }
    Ok(())
}

/// Reject any configured property krunc does not model and therefore cannot
/// apply. The OCI runtime-spec's `create` operation requires: "if the runtime
/// cannot apply a property as specified in the configuration, it MUST generate
/// an error and a new container MUST NOT be created." Silently ignoring a
/// property would violate that, so krunc fails closed.
fn reject_unmodeled(
    scope: &str,
    extra: &HashMap<String, serde_json::Value>,
    allow: &[&str],
) -> Result<(), OciError> {
    for key in extra.keys() {
        if !allow.contains(&key.as_str()) {
            let prefix = if scope.is_empty() { String::new() } else { format!("{scope}.") };
            return Err(OciError::UnsupportedProperty(format!("{prefix}{key}")));
        }
    }
    Ok(())
}

/// Translate a parsed OCI config (from `bundle`) into a validated [`DomainSpec`].
pub fn config_to_spec(bundle: &Path, cfg: &OciConfig) -> Result<DomainSpec, OciError> {
    let process = cfg.process.as_ref().ok_or(OciError::Missing("process"))?;
    if process.args.is_empty() {
        return Err(OciError::Missing("process.args"));
    }
    // A terminal must be allocated when `process.terminal` is true (runtime-spec
    // config: a pseudoterminal pair is allocated and duplicated on the process's
    // stdio). krunc does not allocate terminals, so it must reject — not ignore —
    // the request. (How a runtime hands the terminal master to its caller, e.g.
    // runc's `--console-socket`, is a CLI convention outside the runtime-spec.)
    if process.terminal {
        return Err(OciError::UnsupportedProperty("process.terminal".into()));
    }
    // krunc execs the entrypoint at the rootfs root; it does not chdir, so it
    // cannot honor a non-root `process.cwd` (REQUIRED by the spec). Reject one
    // rather than silently running the process in the wrong directory.
    if let Some(cwd) = &process.cwd {
        if !cwd.is_empty() && cwd != "/" {
            return Err(OciError::UnsupportedProperty(
                "process.cwd other than \"/\"".into(),
            ));
        }
    }
    // krunc applies process.user.uid/gid but does not set supplementary groups,
    // so a non-empty additionalGids must be rejected rather than ignored.
    if let Some(user) = &process.user {
        if !user.additional_gids.is_empty() {
            return Err(OciError::UnsupportedProperty("process.user.additionalGids".into()));
        }
    }
    let root = cfg.root.as_ref().ok_or(OciError::Missing("root"))?;
    if root.path.is_empty() {
        return Err(OciError::Missing("root.path"));
    }

    // Fail closed on any configured property krunc does not model/apply.
    // (`annotations` is now a typed field, so it no longer appears in `extra`.)
    reject_unmodeled("", &cfg.extra, &[])?;
    reject_unmodeled("process", &process.extra, &[])?;
    if let Some(linux) = &cfg.linux {
        reject_unmodeled("linux", &linux.extra, &[])?;
        if let Some(res) = &linux.resources {
            reject_unmodeled("linux.resources", &res.extra, &[])?;
        }
    }

    let mut namespaces = 0u32;
    let mut uid_maps: Vec<IdMap> = Vec::new();
    let mut gid_maps: Vec<IdMap> = Vec::new();
    let mut masked_paths = Vec::new();
    let mut readonly_paths = Vec::new();
    let mut sysctls: Vec<String> = Vec::new();
    if let Some(linux) = &cfg.linux {
        for ns in &linux.namespaces {
            if ns.path.is_some() {
                return Err(OciError::Unsupported(
                    "joining an existing namespace (namespaces[].path)",
                ));
            }
            namespaces |= ns_flag(&ns.ns_type)?;
        }
        // linux.uid/gidMappings: the kernel module writes /proc/<pid>/{uid,gid}_map
        // for the container's user namespace. Mappings are only meaningful with a
        // user namespace, so require one (per the runtime-spec, a property that
        // cannot be applied must error, not be silently ignored). A bare `user`
        // namespace with no mappings is still created as specified.
        if (!linux.uid_mappings.is_empty() || !linux.gid_mappings.is_empty())
            && namespaces & NS_USER == 0
        {
            return Err(OciError::Unsupported(
                "uid/gidMappings without a user namespace",
            ));
        }
        uid_maps = translate_id_maps(&linux.uid_mappings)?;
        gid_maps = translate_id_maps(&linux.gid_mappings)?;
        masked_paths = linux.masked_paths.clone();
        readonly_paths = linux.readonly_paths.clone();
        // Translate linux.sysctl into "<relpath>=<value>" entries (the sysctl name
        // with `.` -> `/`). Only sysctls confined to a kernel namespace the
        // container OWNS are allowed (mirrors runc): the container init applies
        // them while still uid 0 in the host's init_user_ns, so a host-global
        // sysctl (e.g. `kernel.core_pattern`, `kernel.modprobe`) would change HOST
        // state (a classic container->host-root escape). Such names are rejected
        // per the runtime-spec rather than applied. Names are validated so they
        // cannot escape /proc/sys; values are single safe lines. Sorted for a
        // deterministic spec.
        let has_ipc_ns = namespaces & NS_IPC != 0;
        let has_net_ns = namespaces & NS_NET != 0;
        let mut entries: Vec<(String, String)> = Vec::with_capacity(linux.sysctl.len());
        for (k, v) in &linux.sysctl {
            if !sysctl_namespaced(k, has_ipc_ns, has_net_ns) {
                return Err(OciError::UnsupportedProperty(format!(
                    "linux.sysctl {k:?} (not in a kernel namespace the container owns)"
                )));
            }
            entries.push((sysctl_relpath(k)?, sysctl_value(v)?.to_string()));
        }
        entries.sort();
        sysctls = entries.into_iter().map(|(p, v)| format!("{p}={v}")).collect();
    }

    let mut flags = 0u64;
    if process.no_new_privileges {
        flags |= OPT_NO_NEW_PRIVS;
    }
    // A read-only rootfs is enforced by the kernel module: it bind-mounts the
    // rootfs onto itself and, once the submounts are in place, remounts it
    // read-only (MS_REMOUNT|MS_BIND|MS_RDONLY) so the rootfs files are immutable
    // while writable submounts (e.g. /tmp) stay writable. The module fails closed
    // (refuses to exec) if it cannot apply the seal, so this is never silently
    // left writable.
    if root.readonly {
        flags |= OPT_ROOTFS_RO;
    }

    // A present `capabilities` object means the caller is managing caps and the
    // five sets must be applied exactly — even if all empty (drop everything).
    // Absent, krunc leaves the task's caps as they are.
    let caps_present = process.capabilities.is_some();
    let (cap_bounding, cap_effective, cap_permitted, cap_inheritable, cap_ambient) =
        match &process.capabilities {
            Some(c) => (
                caps_to_mask(&c.bounding)?,
                caps_to_mask(&c.effective)?,
                caps_to_mask(&c.permitted)?,
                caps_to_mask(&c.inheritable)?,
                caps_to_mask(&c.ambient)?,
            ),
            None => (0, 0, 0, 0, 0),
        };

    let mut rlimits = Vec::with_capacity(process.rlimits.len());
    for rl in &process.rlimits {
        let resource = rlimit_resource(&rl.limit_type)
            .ok_or(OciError::Unsupported("process.rlimits[].type"))?;
        rlimits.push(Rlimit { resource, soft: rl.soft, hard: rl.hard });
    }

    let mounts = cfg
        .mounts
        .iter()
        .map(|m| {
            check_mount_options(&m.options)?;
            let (flags, is_bind) = mount_flags(&m.options);
            // For a bind, the krunc mount helper wants no fs type and the source
            // path; otherwise pass the declared type and source.
            let fs_type = if is_bind { String::new() } else { m.mount_type.clone() };
            Ok(Mount {
                destination: m.destination.clone(),
                fs_type,
                source: m.source.clone(),
                flags,
            })
        })
        .collect::<Result<Vec<_>, OciError>>()?;

    let spec = DomainSpec {
        rootfs: resolve_rootfs(bundle, &root.path),
        hostname: cfg.hostname.clone().unwrap_or_default(),
        argv: process.args.clone(),
        env: process.env.clone(),
        namespaces,
        uid_maps,
        gid_maps,
        flags,
        caps_present,
        cap_bounding,
        cap_effective,
        cap_permitted,
        cap_inheritable,
        cap_ambient,
        masked_paths,
        readonly_paths,
        rlimits,
        oom_score_adj: process.oom_score_adj,
        uid: process.user.as_ref().map(|u| u.uid).unwrap_or(0),
        gid: process.user.as_ref().map(|u| u.gid).unwrap_or(0),
        mounts,
        sysctls,
    };
    spec.validate()?;
    Ok(spec)
}

/// Whether an OCI sysctl is confined to a kernel namespace the container OWNS, so
/// setting it cannot affect the host. Mirrors runc's safe set: the IPC-namespaced
/// sysctls (`kernel.sem`, `kernel.shm*`, `kernel.msg*`, `fs.mqueue.*`) require an
/// IPC namespace; `net.*` requires a network namespace. Everything else (e.g.
/// `kernel.core_pattern`, `kernel.modprobe`, `kernel.kptr_restrict`) is
/// host-global and must be rejected — the container init writes sysctls while
/// still privileged in the host's init_user_ns, so a global write would be a
/// container->host escape.
fn sysctl_namespaced(name: &str, has_ipc_ns: bool, has_net_ns: bool) -> bool {
    if name.starts_with("net.") {
        return has_net_ns;
    }
    let ipc = name == "kernel.sem"
        || name.starts_with("kernel.shm")
        || name.starts_with("kernel.msg")
        || name.starts_with("fs.mqueue.");
    ipc && has_ipc_ns
}

/// Convert an OCI sysctl name (e.g. `net.ipv4.ip_forward`) into a path relative
/// to `/proc/sys` (`net/ipv4/ip_forward`), rejecting anything that could escape
/// `/proc/sys`: path traversal (`..`), absolute or trailing-slash names, empty
/// components, or characters outside the conventional sysctl set.
fn sysctl_relpath(name: &str) -> Result<String, OciError> {
    let bad = || OciError::UnsupportedProperty(format!("linux.sysctl name {name:?}"));
    if name.is_empty() {
        return Err(bad());
    }
    if !name
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'/' | b'_' | b'-'))
    {
        return Err(bad());
    }
    let rel = name.replace('.', "/");
    if rel.starts_with('/') || rel.ends_with('/') || rel.split('/').any(|c| c.is_empty() || c == "..")
    {
        return Err(bad());
    }
    Ok(rel)
}

/// Validate a sysctl value: a single line with no NUL or newline (so it cannot be
/// used to inject additional writes). Returned unchanged.
fn sysctl_value(value: &str) -> Result<&str, OciError> {
    if value.bytes().any(|b| b == 0 || b == b'\n') {
        return Err(OciError::UnsupportedProperty(format!(
            "linux.sysctl value {value:?}"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    use krunc_abi::Op;

    const SAMPLE: &str = r#"{
      "ociVersion": "1.0.2-dev",
      "hostname": "oci-demo",
      "process": {
        "terminal": false,
        "user": { "uid": 65534, "gid": 65534 },
        "args": ["/bin/sh", "/init.sh"],
        "env": ["PATH=/bin:/sbin", "TERM=linux"],
        "cwd": "/",
        "noNewPrivileges": true,
        "capabilities": {
          "bounding": ["CAP_NET_BIND_SERVICE", "CAP_KILL", "CAP_AUDIT_WRITE"],
          "effective": ["CAP_KILL"]
        },
        "oomScoreAdj": -500,
        "rlimits": [
          { "type": "RLIMIT_NOFILE", "soft": 1024, "hard": 4096 },
          { "type": "RLIMIT_CORE", "soft": 0, "hard": 0 }
        ]
      },
      "root": { "path": "rootfs", "readonly": false },
      "linux": {
        "namespaces": [
          { "type": "pid" }, { "type": "mount" }, { "type": "uts" },
          { "type": "ipc" }, { "type": "network" }
        ],
        "maskedPaths": ["/proc/kcore", "/proc/sysrq-trigger"],
        "readonlyPaths": ["/proc/sys", "/bin"]
      },
      "mounts": [
        { "destination": "/proc", "type": "proc", "source": "proc" },
        { "destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
          "options": ["nosuid", "nodev", "noexec"] },
        { "destination": "/etc/hosts", "type": "bind", "source": "/host/hosts",
          "options": ["rbind", "ro"] }
      ]
    }"#;

    #[test]
    fn translates_sample_bundle() {
        let cfg = parse_config(SAMPLE).unwrap();
        let spec = config_to_spec(Path::new("/bundle"), &cfg).unwrap();

        assert_eq!(spec.rootfs, "/bundle/rootfs");
        assert_eq!(spec.hostname, "oci-demo");
        assert_eq!(spec.argv, vec!["/bin/sh", "/init.sh"]);
        assert_eq!(spec.env, vec!["PATH=/bin:/sbin", "TERM=linux"]);
        assert_eq!(spec.namespaces, NS_PID | NS_MOUNT | NS_UTS | NS_IPC | NS_NET);
        assert_eq!(spec.flags, OPT_NO_NEW_PRIVS);
        // krunc does not apply user-namespace ID mappings, so the translated
        // spec carries none (and the sample config declares none).
        assert!(spec.uid_maps.is_empty());
        assert!(spec.gid_maps.is_empty());
        let expect_caps = (1u64 << 10) | (1u64 << 5) | (1u64 << 29);
        assert!(spec.caps_present);
        assert_eq!(spec.cap_bounding, expect_caps);
        // effective is specified separately (just CAP_KILL); permitted/inheritable/
        // ambient are unset, so they must be empty -- not silently equal to bounding.
        assert_eq!(spec.cap_effective, 1u64 << 5);
        assert_eq!(spec.cap_permitted, 0);
        assert_eq!(spec.cap_inheritable, 0);
        assert_eq!(spec.cap_ambient, 0);
        assert_eq!(spec.masked_paths, vec!["/proc/kcore", "/proc/sysrq-trigger"]);
        assert_eq!(spec.readonly_paths, vec!["/proc/sys", "/bin"]);
        assert_eq!(
            spec.rlimits,
            vec![
                Rlimit { resource: 7, soft: 1024, hard: 4096 },
                Rlimit { resource: 4, soft: 0, hard: 0 },
            ]
        );
        assert_eq!(spec.oom_score_adj, Some(-500));
        assert_eq!(spec.uid, 65534);
        assert_eq!(spec.gid, 65534);
        // mounts: proc (no flags), tmpfs /tmp (nosuid|nodev|noexec=0xe),
        // and a recursive read-only bind (type cleared, MS_BIND|MS_REC|MS_RDONLY).
        assert_eq!(spec.mounts.len(), 3);
        assert_eq!(spec.mounts[0].destination, "/proc");
        assert_eq!(spec.mounts[0].fs_type, "proc");
        assert_eq!(spec.mounts[1].destination, "/tmp");
        assert_eq!(spec.mounts[1].flags, 2 | 4 | 8);
        assert_eq!(spec.mounts[2].fs_type, ""); // bind clears the type
        assert_eq!(spec.mounts[2].flags, 4096 | 16384 | 1);
    }

    #[test]
    fn translated_spec_round_trips_through_abi() {
        let cfg = parse_config(SAMPLE).unwrap();
        let spec = config_to_spec(Path::new("/bundle"), &cfg).unwrap();
        let buf = spec.encode(Op::Create).unwrap();
        let (op, decoded) = krunc_abi::decode(&buf).unwrap();
        assert_eq!(op, Op::Create);
        assert_eq!(decoded, spec);
    }

    #[test]
    fn absolute_rootfs_kept() {
        let cfg = parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"/abs/root"}}"#).unwrap();
        let spec = config_to_spec(Path::new("/bundle"), &cfg).unwrap();
        assert_eq!(spec.rootfs, "/abs/root");
    }

    #[test]
    fn missing_process_rejected() {
        let cfg = parse_config(r#"{"root":{"path":"rootfs"}}"#).unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::Missing("process"))
        ));
    }

    #[test]
    fn missing_args_rejected() {
        let cfg = parse_config(r#"{"process":{"args":[]},"root":{"path":"r"}}"#).unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::Missing("process.args"))
        ));
    }

    #[test]
    fn missing_root_rejected() {
        let cfg = parse_config(r#"{"process":{"args":["/x"]}}"#).unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::Missing("root"))
        ));
    }

    #[test]
    fn empty_capabilities_drops_all() {
        // An explicit (but empty) capabilities object means "drop everything":
        // caps must be marked present so the kernel applies the all-empty set
        // rather than treating it as "leave caps untouched".
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"capabilities":{"bounding":[],"effective":[],"permitted":[],"inheritable":[],"ambient":[]}},"root":{"path":"r"}}"#,
        )
        .unwrap();
        let spec = config_to_spec(Path::new("/b"), &cfg).unwrap();
        assert!(spec.caps_present);
        assert_eq!(spec.cap_bounding, 0);
        assert_eq!(spec.cap_effective, 0);
    }

    #[test]
    fn no_capabilities_leaves_caps_untouched() {
        // No capabilities object at all -> caps_present false (the kernel leaves
        // the task's capability state as-is).
        let cfg =
            parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"r"}}"#).unwrap();
        let spec = config_to_spec(Path::new("/b"), &cfg).unwrap();
        assert!(!spec.caps_present);
    }

    #[test]
    fn nonroot_cwd_rejected() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/app"},"root":{"path":"r"}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn root_cwd_accepted() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"}}"#,
        )
        .unwrap();
        assert!(config_to_spec(Path::new("/b"), &cfg).is_ok());
    }

    #[test]
    fn additional_gids_rejected() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"user":{"uid":0,"gid":0,"additionalGids":[10]}},"root":{"path":"r"}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn terminal_rejected() {
        // process.terminal=true: krunc cannot allocate a terminal, so it must
        // error rather than silently run the process without one.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"terminal":true},"root":{"path":"r"}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn unmodeled_property_rejected() {
        // an unmodeled linux property (rootfsPropagation) -> rejected, not silently
        // ignored.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"rootfsPropagation":"private"}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn sysctl_applied_and_path_safe() {
        // net.* is allowed only with a network namespace; then names become
        // /proc/sys-relative paths.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"namespaces":[{"type":"network"}],"sysctl":{"net.ipv4.ip_forward":"1"}}}"#,
        )
        .unwrap();
        let spec = config_to_spec(Path::new("/b"), &cfg).unwrap();
        assert_eq!(spec.sysctls, vec!["net/ipv4/ip_forward=1".to_string()]);
        // an IPC-namespaced sysctl is allowed with an IPC namespace.
        let ipc = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"namespaces":[{"type":"ipc"}],"sysctl":{"kernel.shmmax":"4096"}}}"#,
        )
        .unwrap();
        assert_eq!(
            config_to_spec(Path::new("/b"), &ipc).unwrap().sysctls,
            vec!["kernel/shmmax=4096".to_string()]
        );
        // a path-traversal sysctl name is rejected (cannot escape /proc/sys).
        let evil = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"namespaces":[{"type":"network"}],"sysctl":{"../secret":"x"}}}"#,
        )
        .unwrap();
        assert!(config_to_spec(Path::new("/b"), &evil).is_err());
        // a value with a newline (write-injection attempt) is rejected.
        let nl = parse_config(
            "{\"process\":{\"args\":[\"/x\"],\"cwd\":\"/\"},\"root\":{\"path\":\"r\"},\"linux\":{\"namespaces\":[{\"type\":\"ipc\"}],\"sysctl\":{\"kernel.sem\":\"a\\nb\"}}}",
        )
        .unwrap();
        assert!(config_to_spec(Path::new("/b"), &nl).is_err());
    }

    #[test]
    fn sysctl_host_global_rejected() {
        // A host-global (non-namespaced) sysctl must be rejected: the container
        // init applies it while still privileged in the host's init_user_ns, so a
        // write would change HOST state (e.g. kernel.core_pattern -> root escape).
        for bad in [
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"namespaces":[{"type":"network"},{"type":"ipc"}],"sysctl":{"kernel.core_pattern":"|/evil"}}}"#,
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"namespaces":[{"type":"ipc"}],"sysctl":{"kernel.modprobe":"/evil"}}}"#,
            // net.* without a network namespace would hit the host's net sysctls.
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"sysctl":{"net.ipv4.ip_forward":"1"}}}"#,
            // an IPC sysctl without an IPC namespace.
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"sysctl":{"kernel.shmmax":"4096"}}}"#,
        ] {
            let cfg = parse_config(bad).unwrap();
            assert!(
                matches!(
                    config_to_spec(Path::new("/b"), &cfg),
                    Err(OciError::UnsupportedProperty(_))
                ),
                "must reject: {bad}"
            );
        }
    }

    #[test]
    fn unmodeled_resource_rejected() {
        // linux.resources.devices (the device cgroup) is not applied -> rejected.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"resources":{"devices":[{"allow":false,"access":"rwm"}]}}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn id_mappings_translated() {
        // With a user namespace, uid/gidMappings are now translated into the ABI
        // (the kernel writes /proc/<pid>/{uid,gid}_map). Verify they survive.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"namespaces":[{"type":"user"}],
                "uidMappings":[{"containerID":0,"hostID":100000,"size":65536}],
                "gidMappings":[{"containerID":0,"hostID":100000,"size":65536}]}}"#,
        )
        .unwrap();
        let spec = config_to_spec(Path::new("/b"), &cfg).unwrap();
        assert_eq!(spec.namespaces & NS_USER, NS_USER);
        assert_eq!(spec.uid_maps.len(), 1);
        assert_eq!(spec.uid_maps[0].container_id, 0);
        assert_eq!(spec.uid_maps[0].host_id, 100000);
        assert_eq!(spec.uid_maps[0].size, 65536);
        assert_eq!(spec.gid_maps.len(), 1);
        assert_eq!(spec.gid_maps[0].host_id, 100000);
    }

    #[test]
    fn id_mappings_without_user_namespace_rejected() {
        // uid/gidMappings are only meaningful with a user namespace; without one
        // krunc errors rather than silently ignoring them.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"namespaces":[{"type":"pid"}],
                "uidMappings":[{"containerID":0,"hostID":100000,"size":65536}]}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::Unsupported(_))
        ));
    }

    #[test]
    fn id_mapping_size_zero_rejected() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"namespaces":[{"type":"user"}],
                "uidMappings":[{"containerID":0,"hostID":100000,"size":0}]}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn unsupported_mount_option_rejected() {
        // A tmpfs data option (size=) cannot be applied by krunc (it passes no
        // per-fs data string), so it is rejected rather than silently dropped --
        // dropping e.g. `mode=` could even loosen permissions.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"mounts":[{"destination":"/tmp","type":"tmpfs","source":"tmpfs","options":["nosuid","size=64m"]}]}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn mount_propagation_option_rejected() {
        // Mount-propagation options are not applied by krunc -> rejected.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"mounts":[{"destination":"/d","type":"bind","source":"/s","options":["rbind","rprivate"]}]}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnsupportedProperty(_))
        ));
    }

    #[test]
    fn must_mount_option_flags_applied() {
        // The runtime-spec lists these flag options as MUST-implement; krunc maps
        // them to MS_* flags rather than rejecting them. `defaults` is a no-op.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"mounts":[{"destination":"/m","type":"tmpfs","source":"tmpfs","options":["defaults","nosuid","async","dirsync","lazytime","iversion"]}]}"#,
        )
        .unwrap();
        let spec = config_to_spec(Path::new("/b"), &cfg).unwrap();
        let f = spec.mounts[0].flags;
        assert_eq!(f & 2, 2, "nosuid (MS_NOSUID)");
        assert_eq!(f & 128, 128, "dirsync (MS_DIRSYNC)");
        assert_eq!(f & (1 << 25), 1 << 25, "lazytime (MS_LAZYTIME)");
        assert_eq!(f & (1 << 23), 1 << 23, "iversion (MS_I_VERSION)");
        assert_eq!(f & 16, 0, "async clears MS_SYNCHRONOUS");
    }

    #[test]
    fn unknown_struct_fields_rejected() {
        // Unmodeled fields in leaf structs must not be silently dropped by serde:
        // deny_unknown_fields turns each into a parse error. These are all real
        // runtime-spec fields krunc does not apply.
        // process.user.umask
        assert!(matches!(
            parse_config(r#"{"process":{"args":["/x"],"user":{"uid":0,"gid":0,"umask":18}},"root":{"path":"r"}}"#),
            Err(OciError::Json(_))
        ));
        // linux.resources.memory.swap
        assert!(matches!(
            parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"resources":{"memory":{"limit":1024,"swap":2048}}}}"#),
            Err(OciError::Json(_))
        ));
        // per-mount uidMappings (id-mapped mounts)
        assert!(matches!(
            parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"r"},"mounts":[{"destination":"/d","type":"bind","source":"/s","uidMappings":[{"containerID":0,"hostID":0,"size":1}]}]}"#),
            Err(OciError::Json(_))
        ));
    }

    #[test]
    fn seccomp_and_readonly_rootfs_rejected() {
        // krunc no longer applies seccomp or seals an immutable rootfs (Landlock
        // dropped), so both are rejected rather than silently ignored. `linux.seccomp`
        // is an unmodeled `linux` property; `root.readonly=true` is rejected explicitly.
        let sc = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r"},"linux":{"seccomp":{"defaultAction":"SCMP_ACT_ALLOW"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &sc),
            Err(OciError::UnsupportedProperty(_))
        ));
        let ro = parse_config(
            r#"{"process":{"args":["/x"],"cwd":"/"},"root":{"path":"r","readonly":true}}"#,
        )
        .unwrap();
        let ro_spec = config_to_spec(Path::new("/b"), &ro).unwrap();
        assert!(ro_spec.flags & OPT_ROOTFS_RO != 0);
    }

    #[test]
    fn parses_example_bundle() {
        // The shipped manual-testing bundle must always parse and translate under
        // the strict rules (guards against drift between it and the parser).
        let json = include_str!("../../../examples/bundle/config.json");
        let cfg = parse_config(json).expect("example bundle must parse");
        config_to_spec(Path::new("/bundle"), &cfg).expect("example bundle must translate");
    }

    #[test]
    fn annotations_allowed() {
        // annotations are caller metadata (not applied to the container) -> allowed.
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"annotations":{"foo":"bar"}}"#,
        )
        .unwrap();
        assert!(config_to_spec(Path::new("/b"), &cfg).is_ok());
    }

    #[test]
    fn unknown_capability_rejected() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"],"capabilities":{"bounding":["CAP_BOGUS"]}},"root":{"path":"r"}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::UnknownCapability(_))
        ));
    }

    #[test]
    fn time_namespace_unsupported() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"namespaces":[{"type":"time"}]}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::Unsupported(_))
        ));
    }

    #[test]
    fn joining_namespace_path_unsupported() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"linux":{"namespaces":[{"type":"net","path":"/proc/1/ns/net"}]}}"#,
        )
        .unwrap();
        assert!(matches!(
            config_to_spec(Path::new("/b"), &cfg),
            Err(OciError::Unsupported(_))
        ));
    }

    #[test]
    fn cap_table_is_consistent() {
        assert_eq!(cap_bit("CAP_SYS_ADMIN"), Some(21));
        assert_eq!(cap_bit("CAP_CHOWN"), Some(0));
        assert_eq!(cap_bit("CAP_CHECKPOINT_RESTORE"), Some(40));
        assert_eq!(cap_bit("nope"), None);
    }

    #[test]
    fn invalid_json_rejected() {
        assert!(matches!(parse_config("{not json"), Err(OciError::Json(_))));
    }

    #[test]
    fn cgroup_config_extracted() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},
                "linux":{"cgroupsPath":"krunc/c1","resources":{"pids":{"limit":64},
                "memory":{"limit":33554432},"cpu":{"quota":20000,"period":100000,"shares":512}}}}"#,
        )
        .unwrap();
        let cg = cgroup_config(&cfg);
        assert_eq!(cg.path.as_deref(), Some("krunc/c1"));
        assert_eq!(cg.pids_limit, Some(64));
        assert_eq!(cg.memory_limit, Some(33554432));
        assert_eq!(cg.cpu_max.as_deref(), Some("20000 100000"));
        // shares 512 maps into the cgroup-v2 weight range (1..=10000).
        assert!(matches!(cg.cpu_weight, Some(w) if (1..=10000).contains(&w)));
    }

    #[test]
    fn cgroup_negative_memory_is_unlimited() {
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},
                "linux":{"resources":{"memory":{"limit":-1}}}}"#,
        )
        .unwrap();
        assert_eq!(cgroup_config(&cfg).memory_limit, None);
    }

    #[test]
    fn cgroup_config_absent() {
        let cfg = parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"r"}}"#).unwrap();
        assert_eq!(cgroup_config(&cfg), CgroupConfig::default());
    }

    #[test]
    fn bpf_lsm_annotation_parsed() {
        let none = parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"r"}}"#).unwrap();
        assert_eq!(bpf_lsm_mode(&none).unwrap(), None);

        let block = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"annotations":{"org.krunc.bpf-lsm":"block"}}"#,
        )
        .unwrap();
        assert_eq!(bpf_lsm_mode(&block).unwrap(), Some(BpfLsmMode::Block));
        assert_eq!(bpf_lsm_mode(&block).unwrap().unwrap().as_arg(), "block");

        let kill = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"annotations":{"org.krunc.bpf-lsm":"kill"}}"#,
        )
        .unwrap();
        assert_eq!(bpf_lsm_mode(&kill).unwrap(), Some(BpfLsmMode::Kill));

        // A typo must fail closed, not silently disable enforcement.
        let bad = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"r"},"annotations":{"org.krunc.bpf-lsm":"on"}}"#,
        )
        .unwrap();
        assert!(bpf_lsm_mode(&bad).is_err());
    }

    #[test]
    fn annotations_do_not_trip_unknown_field_rejection() {
        // annotations is a typed field now; an arbitrary annotation key must be
        // accepted (not rejected as an unmodeled top-level property).
        let cfg = parse_config(
            r#"{"process":{"args":["/x"]},"root":{"path":"rootfs"},"annotations":{"com.example/foo":"bar"}}"#,
        )
        .unwrap();
        assert!(config_to_spec(Path::new("/b"), &cfg).is_ok());
    }

    /// The OCI config.json is the primary untrusted input to krunc's userspace.
    /// `parse_config` then `config_to_spec` must NEVER panic on it, no matter how
    /// malformed — they must always return `Ok`/`Err`. This deterministically
    /// fuzzes the whole JSON→spec front end with random bytes, byte-mutated valid
    /// configs, and JSON-token soup, asserting panic-freedom (a panic in the CLI
    /// is a denial of service on the runtime).
    #[test]
    fn config_pipeline_never_panics_on_arbitrary_input() {
        use std::panic::{catch_unwind, AssertUnwindSafe};

        // splitmix64 PRNG (deterministic, no external dependency).
        let mut state: u64 = 0x0BAD_C0DE_DEAD_BEEF;
        let mut next = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let try_pipeline = |bytes: &[u8]| {
            catch_unwind(AssertUnwindSafe(|| {
                // Lossily treat the bytes as text — JSON input is UTF-8 in practice
                // and parse_config takes &str; invalid UTF-8 simply parse-errors.
                let s = String::from_utf8_lossy(bytes);
                if let Ok(cfg) = parse_config(&s) {
                    let _ = config_to_spec(Path::new("/bundle"), &cfg);
                }
            }))
        };

        // 1. Purely random byte buffers.
        for _ in 0..20_000 {
            let len = (next() % 600) as usize;
            let buf: Vec<u8> = (0..len).map(|_| (next() & 0xff) as u8).collect();
            assert!(try_pipeline(&buf).is_ok(), "panicked on random bytes");
        }

        // 2. The valid SAMPLE config with random single-byte mutations — exercises
        //    the structured paths with subtly-broken inputs.
        let base = SAMPLE.as_bytes();
        for _ in 0..20_000 {
            let mut buf = base.to_vec();
            let nmut = 1 + (next() % 8) as usize;
            for _ in 0..nmut {
                let idx = (next() as usize) % buf.len();
                buf[idx] = (next() & 0xff) as u8;
            }
            assert!(try_pipeline(&buf).is_ok(), "panicked on mutated SAMPLE");
        }

        // 3. Random soup of JSON tokens — structurally JSON-ish but semantically
        //    arbitrary, to reach the typed-field validation logic.
        let toks: [&str; 18] = [
            "{", "}", "[", "]", ":", ",", "\"process\"", "\"args\"", "\"root\"",
            "\"path\"", "\"linux\"", "\"namespaces\"", "\"type\"", "\"pid\"",
            "null", "true", "-1", "1e999",
        ];
        for _ in 0..20_000 {
            let n = (next() % 40) as usize;
            let mut s = String::new();
            for _ in 0..n {
                s.push_str(toks[(next() as usize) % toks.len()]);
            }
            assert!(try_pipeline(s.as_bytes()).is_ok(), "panicked on token soup");
        }
    }

    /// Every config that translates must produce a spec that the ABI can encode
    /// and the (mirrored) decoder can read back, with the key fields surviving the
    /// round trip. This fuzzes a structured-but-varied family of valid configs and
    /// checks the full JSON→spec→encode→decode pipeline end-to-end.
    #[test]
    fn valid_configs_round_trip_through_abi() {
        use krunc_abi::{decode, Op, OPT_NO_NEW_PRIVS};

        let mut state: u64 = 0xFEED_FACE_CAFE_0001;
        let mut next = move || {
            state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        };
        let caps = ["CAP_KILL", "CAP_CHOWN", "CAP_NET_BIND_SERVICE", "CAP_SETUID"];

        for _ in 0..2_000 {
            let uid = (next() % 70000) as u32;
            let gid = (next() % 70000) as u32;
            let nnp = next() & 1 == 0;
            let ncap = (next() % (caps.len() as u64 + 1)) as usize;
            let bounding: Vec<String> = caps[..ncap].iter().map(|c| format!("{c:?}")).collect();
            let nofile = 256 + (next() % 4096);
            let with_tmpfs = next() & 1 == 0;
            let mounts = if with_tmpfs {
                r#"{ "destination": "/tmp", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid"] },"#
            } else {
                ""
            };
            let json = format!(
                r#"{{
                  "ociVersion": "1.0.2-dev",
                  "hostname": "fuzz-{uid}",
                  "process": {{
                    "user": {{ "uid": {uid}, "gid": {gid} }},
                    "args": ["/bin/app", "--id={gid}"],
                    "env": ["PATH=/bin"],
                    "cwd": "/",
                    "noNewPrivileges": {nnp},
                    "capabilities": {{ "bounding": [{caps_csv}] }},
                    "rlimits": [{{ "type": "RLIMIT_NOFILE", "soft": {nofile}, "hard": {nofile} }}]
                  }},
                  "root": {{ "path": "rootfs", "readonly": false }},
                  "linux": {{ "namespaces": [{{ "type": "pid" }}, {{ "type": "mount" }}] }},
                  "mounts": [{mounts} {{ "destination": "/proc", "type": "proc", "source": "proc" }}]
                }}"#,
                caps_csv = bounding.join(", "),
            );

            let cfg = parse_config(&json).expect("generated config must parse");
            let spec = config_to_spec(Path::new("/bundle"), &cfg).expect("must translate");
            let blob = spec.encode(Op::Create).expect("must encode");
            let (op, decoded) = decode(&blob).expect("must decode");
            assert_eq!(op, Op::Create);
            assert_eq!(decoded.uid, uid);
            assert_eq!(decoded.gid, gid);
            assert_eq!(decoded.flags & OPT_NO_NEW_PRIVS != 0, nnp);
            assert_eq!(decoded.argv, vec!["/bin/app".to_string(), format!("--id={gid}")]);
            assert_eq!(decoded.hostname, format!("fuzz-{uid}"));
        }
    }
}
