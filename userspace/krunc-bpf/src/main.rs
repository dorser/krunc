//! krunc-bpf — the all-Rust (aya) replacement for `krunc_lsm_loader.c`.
//!
//! It loads krunc's prebuilt BPF-LSM escape-blocking object, attaches every LSM
//! program in it, and pins each link plus the `guarded` map to bpffs so the
//! policy persists after this short-lived process exits. The `krunc` CLI invokes
//! it across the container lifecycle:
//!
//!   krunc-bpf init    <bpf.o> <pin-dir>                 # load + attach + pin (once)
//!   krunc-bpf guard   <pin-dir> <cgroup-dir> block|kill # add a container's cgroup
//!   krunc-bpf unguard <pin-dir> <cgroup-dir>            # drop a container's cgroup
//!
//! `init` is idempotent: if the `guarded` map is already pinned the programs are
//! already attached, so it is a no-op. `guard`/`unguard` only touch the pinned
//! map, so they are cheap and need no reload. Because the links and map are
//! pinned to bpffs, the LSM enforcement stays active independently of any krunc
//! process — exactly the lifetime guarantee a runtime needs.

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::process::exit;

use aya::maps::{HashMap, Map, MapData};
use aya::programs::{Lsm, links::FdLink};
use aya::{Btf, BpfLoader};

/// The guarded vectors, as (BPF program name, LSM hook name) pairs — one per
/// `SEC("lsm/<hook>")` in `bpf/krunc_lsm.bpf.c`.
const PROGRAMS: &[(&str, &str)] = &[
    ("krunc_userns_create", "userns_create"),
    ("krunc_sb_mount", "sb_mount"),
    ("krunc_move_mount", "move_mount"),
    ("krunc_bpf", "bpf"),
    ("krunc_ptrace", "ptrace_access_check"),
    ("krunc_file_open", "file_open"),
];

/// Enforcement mode stored as the `guarded` map value (see krunc_lsm.bpf.c).
const MODE_DENY: u8 = 1; // block: deny the escape with -EPERM, container survives
const MODE_KILL: u8 = 2; // also SIGKILL the container on an escape attempt

type Err = Box<dyn std::error::Error>;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let r = match args.get(1).map(String::as_str) {
        Some("init") if args.len() == 4 => cmd_init(&args[2], &args[3]),
        Some("guard") if args.len() == 5 => cmd_guard(&args[2], &args[3], &args[4]),
        Some("unguard") if args.len() == 4 => cmd_unguard(&args[2], &args[3]),
        _ => {
            eprintln!(
                "usage:\n  {0} init    <bpf.o> <pin-dir>\n  {0} guard   <pin-dir> <cgroup-dir> block|kill\n  {0} unguard <pin-dir> <cgroup-dir>",
                args.first().map(String::as_str).unwrap_or("krunc-bpf")
            );
            exit(2);
        }
    };
    if let Err(e) = r {
        eprintln!("krunc-bpf: {e}");
        exit(1);
    }
}

/// cgroup v2 id == the cgroup directory's inode number (what
/// `bpf_get_current_cgroup_id()` returns on x86_64).
fn cgroup_id(cgroup_dir: &str) -> Result<u64, Err> {
    Ok(fs::metadata(cgroup_dir)?.ino())
}

fn map_pin(pin_dir: &str) -> String {
    format!("{pin_dir}/guarded")
}

/// Load the BPF-LSM object, attach every LSM program, and pin the links + the
/// `guarded` map to `pin_dir` (bpffs). Idempotent: a no-op if already pinned.
fn cmd_init(obj_path: &str, pin_dir: &str) -> Result<(), Err> {
    let map_path = map_pin(pin_dir);
    if Path::new(&map_path).exists() {
        println!("krunc-bpf: already initialized ({map_path})");
        return Ok(());
    }
    fs::create_dir_all(pin_dir)?;

    // Kernel BTF (/sys/kernel/btf/vmlinux): required to load LSM (BTF/trampoline)
    // programs and resolve the hook function signatures.
    let btf = Btf::from_sys_fs()?;
    let mut bpf = BpfLoader::new().btf(Some(&btf)).load_file(obj_path)?;

    // Pin the `guarded` map by name so later `guard`/`unguard` invocations (in
    // separate processes) can reopen it. The object's map carries no auto-pin
    // attribute, so we pin it explicitly; its presence is also the idempotency
    // marker checked above.
    bpf.map_mut("guarded")
        .ok_or("guarded map not found in object")?
        .pin(&map_path)?;

    let mut armed = 0;
    for (name, hook) in PROGRAMS {
        let prog: &mut Lsm = bpf
            .program_mut(name)
            .ok_or_else(|| format!("program {name} not found in {obj_path}"))?
            .try_into()?;
        prog.load(hook, &btf)?;
        let link_id = prog.attach()?;
        // Pin the link to bpffs so the LSM hook stays attached after we exit.
        let fd_link: FdLink = prog.take_link(link_id)?.into();
        fd_link.pin(format!("{pin_dir}/link_{name}"))?;
        armed += 1;
    }

    println!("krunc-bpf: armed {armed} LSM hooks; map pinned at {map_path}");
    Ok(())
}

/// Open the pinned `guarded` map and add `cgroup_dir`'s cgroup id with the given
/// enforcement mode, so the container is now guarded by the (already-attached)
/// LSM programs.
fn cmd_guard(pin_dir: &str, cgroup_dir: &str, mode_arg: &str) -> Result<(), Err> {
    let mode = match mode_arg {
        "block" => MODE_DENY,
        "kill" => MODE_KILL,
        other => return Err(format!("invalid mode {other:?} (expected block|kill)").into()),
    };
    let id = cgroup_id(cgroup_dir)?;
    let map = Map::HashMap(MapData::from_pin(map_pin(pin_dir))?);
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(map)?;
    map.insert(id, mode, 0)?;
    println!("krunc-bpf: guarding cgroup {cgroup_dir} (id {id}) in {mode_arg} mode");
    Ok(())
}

/// Open the pinned `guarded` map and drop `cgroup_dir`'s cgroup id, so the
/// container is no longer guarded (used on `krunc delete`). Tolerates a missing
/// entry/map so teardown is idempotent.
fn cmd_unguard(pin_dir: &str, cgroup_dir: &str) -> Result<(), Err> {
    let map_path = map_pin(pin_dir);
    if !Path::new(&map_path).exists() {
        return Ok(()); // never armed; nothing to do
    }
    let id = cgroup_id(cgroup_dir)?;
    let map = Map::HashMap(MapData::from_pin(map_path)?);
    let mut map: HashMap<_, u64, u8> = HashMap::try_from(map)?;
    let _ = map.remove(&id); // already-absent is fine
    println!("krunc-bpf: unguarded cgroup {cgroup_dir} (id {id})");
    Ok(())
}
