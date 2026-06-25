//! Thin wrapper around the `krunc-bpf` helper binary (the all-Rust/aya BPF-LSM
//! loader). The CLI arms per-container escape-blocking at `create` and tears it
//! down at `delete`. Paths are overridable via env for non-default layouts:
//!
//! * `KRUNC_BPF`      — the `krunc-bpf` binary (default: `krunc-bpf` on `PATH`)
//! * `KRUNC_LSM_BPF`  — the compiled BPF-LSM object (default: `/krunc_lsm.bpf.o`)
//! * `KRUNC_BPF_PIN`  — the bpffs pin directory  (default: `/sys/fs/bpf/krunc`)

use std::process::Command;

fn tool() -> String {
    std::env::var("KRUNC_BPF").unwrap_or_else(|_| "krunc-bpf".to_string())
}

fn bpf_object() -> String {
    std::env::var("KRUNC_LSM_BPF").unwrap_or_else(|_| "/krunc_lsm.bpf.o".to_string())
}

fn pin_dir() -> String {
    std::env::var("KRUNC_BPF_PIN").unwrap_or_else(|_| "/sys/fs/bpf/krunc".to_string())
}

/// Load + attach the BPF-LSM programs (idempotent `init`) and add `cgroup_dir`
/// to the guarded set with `mode` (`block`|`kill`).
pub fn arm(cgroup_dir: &str, mode: &str) -> Result<(), String> {
    run(&["init", &bpf_object(), &pin_dir()])?;
    run(&["guard", &pin_dir(), cgroup_dir, mode])?;
    Ok(())
}

/// Drop `cgroup_dir` from the guarded set (best-effort; `krunc-bpf unguard` is
/// idempotent and a no-op if BPF-LSM was never armed).
pub fn disarm(cgroup_dir: &str) {
    let _ = run(&["unguard", &pin_dir(), cgroup_dir]);
}

fn run(args: &[&str]) -> Result<(), String> {
    let status = Command::new(tool())
        .args(args)
        .status()
        .map_err(|e| format!("spawning {} {:?}: {e}", tool(), args))?;
    if !status.success() {
        return Err(format!("{} {:?} failed ({status})", tool(), args));
    }
    Ok(())
}
