//! cgroup v2 placement. Per krunc's architecture, userspace *configures* the
//! cgroup and the kernel *enforces* it. We support the `pids` controller (the
//! test kernel has `CONFIG_CGROUP_PIDS=y`); more controllers slot in here.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use krunc_oci::CgroupConfig;

const CG_ROOT: &str = "/sys/fs/cgroup";

/// A created cgroup for a container.
pub struct Cgroup {
    dir: PathBuf,
}

impl Cgroup {
    /// Create the cgroup and apply limits if any are configured. Returns `None`
    /// when there is nothing to enforce.
    pub fn create(id: &str, cfg: &CgroupConfig) -> io::Result<Option<Cgroup>> {
        if cfg.pids_limit.is_none()
            && cfg.memory_limit.is_none()
            && cfg.cpu_max.is_none()
            && cfg.cpu_weight.is_none()
        {
            return Ok(None);
        }
        // The set of controllers the leaf needs delegated to it.
        let mut controllers = String::new();
        if cfg.pids_limit.is_some() {
            controllers.push_str("+pids ");
        }
        if cfg.memory_limit.is_some() {
            controllers.push_str("+memory ");
        }
        if cfg.cpu_max.is_some() || cfg.cpu_weight.is_some() {
            controllers.push_str("+cpu ");
        }
        let controllers = controllers.trim_end();

        let dir = dir_for(id, cfg);
        fs::create_dir_all(&dir)?;

        // Enable the controllers on every ancestor's subtree_control so the leaf
        // cgroup can carry their interface files (cgroup-v2 delegation;
        // best-effort — a controller absent from the kernel is simply skipped).
        let _ = fs::write(format!("{CG_ROOT}/cgroup.subtree_control"), controllers);
        let mut cur = PathBuf::from(CG_ROOT);
        for comp in dir.strip_prefix(CG_ROOT).unwrap_or(Path::new("")).components() {
            let next = cur.join(comp);
            if next == dir {
                break; // don't enable on the leaf itself
            }
            let _ = fs::write(next.join("cgroup.subtree_control"), controllers);
            cur = next;
        }

        if let Some(limit) = cfg.pids_limit {
            fs::write(dir.join("pids.max"), limit.to_string())?;
        }
        if let Some(limit) = cfg.memory_limit {
            fs::write(dir.join("memory.max"), limit.to_string())?;
        }
        if let Some(max) = &cfg.cpu_max {
            fs::write(dir.join("cpu.max"), max)?;
        }
        if let Some(weight) = cfg.cpu_weight {
            fs::write(dir.join("cpu.weight"), weight.to_string())?;
        }
        Ok(Some(Cgroup { dir }))
    }

    /// Move `pid` (and its future children) into the cgroup.
    pub fn place(&self, pid: i32) -> io::Result<()> {
        fs::write(self.dir.join("cgroup.procs"), pid.to_string())
    }

    /// The cgroup directory.
    pub fn dir(&self) -> &Path {
        &self.dir
    }
}

/// The cgroup directory for `id`/`cfg` (default `krunc/<id>` under the v2 mount).
pub fn dir_for(id: &str, cfg: &CgroupConfig) -> PathBuf {
    let rel = cfg.path.clone().unwrap_or_else(|| format!("krunc/{id}"));
    Path::new(CG_ROOT).join(rel.trim_start_matches('/'))
}

/// Remove a cgroup directory (best-effort; only succeeds once it is empty).
pub fn remove(dir: &Path) {
    let _ = fs::remove_dir(dir);
}
