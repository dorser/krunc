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

use std::fmt;
use std::path::{Path, PathBuf};

use krunc_abi::{
    DomainSpec, IdMap, NS_CGROUP, NS_IPC, NS_MOUNT, NS_NET, NS_PID, NS_USER, NS_UTS,
    OPT_NO_NEW_PRIVS, OPT_ROOTFS_RO,
};
use serde::Deserialize;

pub mod seccomp;

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
}

/// `config.json` `process.user`.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
#[serde(rename_all = "camelCase")]
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
    /// seccomp syscall policy (compiled to a BPF program for the kernel).
    pub seccomp: Option<Seccomp>,
}

/// `config.json` `linux.seccomp`: the syscall policy. krunc compiles the
/// arg-less subset (see [`seccomp::compile`]) into a classic-BPF program.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Seccomp {
    /// Action applied to syscalls with no matching rule (e.g. `SCMP_ACT_ALLOW`).
    pub default_action: String,
    /// errno returned when `default_action` is `SCMP_ACT_ERRNO` (default EPERM).
    #[serde(default)]
    pub default_errno_ret: Option<u32>,
    /// Target architectures (informational; krunc targets x86-64 only).
    #[serde(default)]
    pub architectures: Vec<String>,
    /// Per-syscall rules, evaluated in order (first match wins).
    #[serde(default)]
    pub syscalls: Vec<SeccompSyscall>,
}

/// One `config.json` `linux.seccomp.syscalls[]` rule.
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SeccompSyscall {
    /// Syscall names this rule applies to.
    #[serde(default)]
    pub names: Vec<String>,
    /// Action for these syscalls (e.g. `SCMP_ACT_ERRNO`).
    pub action: String,
    /// errno returned when `action` is `SCMP_ACT_ERRNO` (default EPERM).
    #[serde(default)]
    pub errno_ret: Option<u32>,
    /// Argument matchers. krunc does not honor these, so a non-empty list makes
    /// compilation fail rather than silently weaken the policy.
    #[serde(default)]
    pub args: Vec<serde_json::Value>,
}

/// `config.json` `linux.resources` (the subset krunc enforces via cgroup v2).
#[derive(Debug, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct Resources {
    /// pids controller.
    pub pids: Option<Pids>,
}

/// `config.json` `linux.resources.pids`.
#[derive(Debug, Deserialize, Default)]
pub struct Pids {
    /// Maximum number of pids (`pids.max`).
    pub limit: i64,
}

/// Cgroup configuration extracted for the CLI to apply (userspace configures the
/// cgroup; the kernel enforces it).
#[derive(Debug, Default, PartialEq, Eq)]
pub struct CgroupConfig {
    /// Path relative to the cgroup-v2 mount (default `krunc/<id>` if absent).
    pub path: Option<String>,
    /// `pids.max`, if set.
    pub pids_limit: Option<i64>,
}

/// Extract the cgroup configuration from a parsed config.
pub fn cgroup_config(cfg: &OciConfig) -> CgroupConfig {
    let linux = cfg.linux.as_ref();
    CgroupConfig {
        path: linux.and_then(|l| l.cgroups_path.clone()),
        pids_limit: linux
            .and_then(|l| l.resources.as_ref())
            .and_then(|r| r.pids.as_ref())
            .map(|p| p.limit),
    }
}

/// A `linux.namespaces` entry.
#[derive(Debug, Deserialize, Default)]
pub struct Namespace {
    /// Namespace type (`pid`, `mount`, `network`, `ipc`, `uts`, `user`, `cgroup`).
    #[serde(rename = "type")]
    pub ns_type: String,
    /// If set, join an existing namespace at this path (not yet supported).
    pub path: Option<String>,
}

/// A `linux.uidMappings`/`gidMappings` entry.
#[derive(Debug, Deserialize, Default)]
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

/// Translate a parsed OCI config (from `bundle`) into a validated [`DomainSpec`].
pub fn config_to_spec(bundle: &Path, cfg: &OciConfig) -> Result<DomainSpec, OciError> {
    let process = cfg.process.as_ref().ok_or(OciError::Missing("process"))?;
    if process.args.is_empty() {
        return Err(OciError::Missing("process.args"));
    }
    let root = cfg.root.as_ref().ok_or(OciError::Missing("root"))?;
    if root.path.is_empty() {
        return Err(OciError::Missing("root.path"));
    }

    let mut namespaces = 0u32;
    let mut uid_maps = Vec::new();
    let mut gid_maps = Vec::new();
    let mut masked_paths = Vec::new();
    let mut readonly_paths = Vec::new();
    let mut seccomp = Vec::new();
    if let Some(linux) = &cfg.linux {
        for ns in &linux.namespaces {
            if ns.path.is_some() {
                return Err(OciError::Unsupported(
                    "joining an existing namespace (namespaces[].path)",
                ));
            }
            namespaces |= ns_flag(&ns.ns_type)?;
        }
        uid_maps = linux
            .uid_mappings
            .iter()
            .map(|m| IdMap { container_id: m.container_id, host_id: m.host_id, size: m.size })
            .collect();
        gid_maps = linux
            .gid_mappings
            .iter()
            .map(|m| IdMap { container_id: m.container_id, host_id: m.host_id, size: m.size })
            .collect();
        masked_paths = linux.masked_paths.clone();
        readonly_paths = linux.readonly_paths.clone();
        if let Some(sc) = &linux.seccomp {
            seccomp = seccomp::compile(sc)?;
        }
    }

    let mut flags = 0u64;
    if process.no_new_privileges {
        flags |= OPT_NO_NEW_PRIVS;
    }
    if root.readonly {
        flags |= OPT_ROOTFS_RO;
    }

    let cap_bounding = match &process.capabilities {
        Some(c) => caps_to_mask(&c.bounding)?,
        None => 0,
    };

    let spec = DomainSpec {
        rootfs: resolve_rootfs(bundle, &root.path),
        hostname: cfg.hostname.clone().unwrap_or_default(),
        argv: process.args.clone(),
        env: process.env.clone(),
        namespaces,
        uid_maps,
        gid_maps,
        flags,
        cap_bounding,
        seccomp,
        masked_paths,
        readonly_paths,
    };
    spec.validate()?;
    Ok(spec)
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
        "user": { "uid": 0, "gid": 0 },
        "args": ["/bin/sh", "/init.sh"],
        "env": ["PATH=/bin:/sbin", "TERM=linux"],
        "cwd": "/",
        "noNewPrivileges": true,
        "capabilities": {
          "bounding": ["CAP_NET_BIND_SERVICE", "CAP_KILL", "CAP_AUDIT_WRITE"]
        }
      },
      "root": { "path": "rootfs", "readonly": true },
      "linux": {
        "namespaces": [
          { "type": "pid" }, { "type": "mount" }, { "type": "uts" },
          { "type": "ipc" }, { "type": "network" }
        ],
        "uidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
        "gidMappings": [ { "containerID": 0, "hostID": 100000, "size": 65536 } ],
        "maskedPaths": ["/proc/kcore", "/proc/sysrq-trigger"],
        "readonlyPaths": ["/proc/sys", "/bin"]
      }
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
        assert_eq!(spec.flags, OPT_NO_NEW_PRIVS | OPT_ROOTFS_RO);
        assert_eq!(
            spec.uid_maps,
            vec![IdMap { container_id: 0, host_id: 100000, size: 65536 }]
        );
        let expect_caps = (1u64 << 10) | (1u64 << 5) | (1u64 << 29);
        assert_eq!(spec.cap_bounding, expect_caps);
        assert_eq!(spec.masked_paths, vec!["/proc/kcore", "/proc/sysrq-trigger"]);
        assert_eq!(spec.readonly_paths, vec!["/proc/sys", "/bin"]);
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
                "linux":{"cgroupsPath":"krunc/c1","resources":{"pids":{"limit":64}}}}"#,
        )
        .unwrap();
        let cg = cgroup_config(&cfg);
        assert_eq!(cg.path.as_deref(), Some("krunc/c1"));
        assert_eq!(cg.pids_limit, Some(64));
    }

    #[test]
    fn cgroup_config_absent() {
        let cfg = parse_config(r#"{"process":{"args":["/x"]},"root":{"path":"r"}}"#).unwrap();
        assert_eq!(cgroup_config(&cfg), CgroupConfig::default());
    }
}
