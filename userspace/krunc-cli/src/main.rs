//! `krunc` — a runc/OCI-compatible CLI that drives the krunc kernel domain.
//!
//! It reads an OCI bundle's `config.json`, translates it to a validated
//! [`krunc_abi::DomainSpec`] (via `krunc-oci`), and issues the lifecycle ioctls
//! to `/dev/krunc`. Per-id state is persisted under `--root` (default
//! `/run/krunc`) like runc, so each subcommand is a separate process.

mod cgroup;
mod device;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

use serde::{Deserialize, Serialize};

use device::{Device, KState};
use krunc_oci::{cgroup_config, config_to_spec, parse_config};

const VERSION: &str = "1.1.0-krunc";
const OCI_VERSION: &str = "1.0.2-dev";

fn die(msg: impl AsRef<str>) -> ! {
    eprintln!("krunc: {}", msg.as_ref());
    exit(1);
}

/// Persisted per-container state (also what `state` prints — the OCI state schema).
#[derive(Serialize, Deserialize)]
struct State {
    #[serde(rename = "ociVersion")]
    oci_version: String,
    id: String,
    status: String,
    pid: i32,
    bundle: String,
    #[serde(rename = "kruncId")]
    krunc_id: u64,
    /// cgroup directory created for this container (for cleanup), if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cgroup: Option<String>,
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (flags, pos) = parse_args(&argv);

    if flags.contains_key("--version") || pos.first().map(String::as_str) == Some("version") {
        print_version();
        return;
    }
    let root = flags
        .get("--root")
        .cloned()
        .unwrap_or_else(|| "/run/krunc".to_string());
    let cmd = pos.first().cloned().unwrap_or_else(|| die("no command"));
    let args = &pos[1..];

    match cmd.as_str() {
        "create" => do_create(&root, &flags, args),
        "run" => do_run(&root, &flags, args),
        "start" => do_start(&root, args),
        "state" => do_state(&root, args),
        "kill" => do_kill(&root, args),
        "delete" => do_delete(&root, &flags, args),
        "list" => do_list(&root),
        "features" => println!(r#"{{"ociVersionMin":"1.0.0","ociVersionMax":"1.0.2-dev"}}"#),
        other => die(format!("unknown command {other:?}")),
    }
}

/// Lenient single-pass parse: known value-taking flags consume the next token;
/// every other `--x` is boolean; non-flags are positionals. Tolerates the global
/// flags that go-runc/containerd pass (`--root`, `--log`, `--log-format`, …).
fn parse_args(args: &[String]) -> (HashMap<String, String>, Vec<String>) {
    const VALUED: &[&str] = &[
        "--root", "--log", "--log-format", "--criu", "--rootless", "--bundle", "-b",
        "--pid-file", "--console-socket", "--preserve-fds", "--process", "--pid",
        "--image", "--rootfs", "--name",
    ];
    let mut flags = HashMap::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
        if a == "--" {
            // POSIX/runc convention: everything after a bare `--` is positional
            // (the container command and its own flags, e.g. `run img -- ls -l`).
            pos.extend_from_slice(&args[i + 1..]);
            break;
        }
        if a.starts_with('-') {
            if let Some(eq) = a.find('=') {
                flags.insert(a[..eq].to_string(), a[eq + 1..].to_string());
            } else if VALUED.contains(&a.as_str()) && i + 1 < args.len() {
                flags.insert(a.clone(), args[i + 1].clone());
                i += 1;
            } else {
                flags.insert(a.clone(), "true".to_string());
            }
        } else {
            pos.push(a.clone());
        }
        i += 1;
    }
    if let Some(b) = flags.get("-b").cloned() {
        flags.insert("--bundle".to_string(), b);
    }
    (flags, pos)
}

fn state_dir(root: &str, id: &str) -> PathBuf {
    Path::new(root).join(id)
}
fn state_path(root: &str, id: &str) -> PathBuf {
    state_dir(root, id).join("state.json")
}

fn load_state(root: &str, id: &str) -> State {
    let raw = fs::read(state_path(root, id))
        .unwrap_or_else(|_| die(format!("container {id:?} does not exist")));
    serde_json::from_slice(&raw).unwrap_or_else(|e| die(format!("corrupt state: {e}")))
}

fn save_state(root: &str, st: &State) {
    let dir = state_dir(root, &st.id);
    fs::create_dir_all(&dir).unwrap_or_else(|e| die(format!("mkdir state: {e}")));
    let json = serde_json::to_vec_pretty(st).expect("serialize state");
    fs::write(state_path(root, &st.id), json).unwrap_or_else(|e| die(format!("write state: {e}")));
}

fn status_str(s: KState) -> &'static str {
    match s {
        KState::Created => "created",
        KState::Running => "running",
        KState::Stopped => "stopped",
    }
}

fn do_create(root: &str, flags: &HashMap<String, String>, args: &[String]) {
    let id = args.first().unwrap_or_else(|| die("usage: create --bundle <dir> <id>"));
    let bundle = bundle_path(flags);
    let st = create_from_bundle(root, flags, id, &bundle);
    eprintln!("created {} (pid {}, krunc id {})", st.id, st.pid, st.krunc_id);
}

/// Resolve and canonicalize the bundle dir from flags (default: cwd).
fn bundle_path(flags: &HashMap<String, String>) -> PathBuf {
    let b = flags.get("--bundle").cloned().unwrap_or_else(|| ".".to_string());
    fs::canonicalize(&b).unwrap_or_else(|e| die(format!("bundle {b:?}: {e}")))
}

/// Shared by `create` and `run`: parse the bundle's `config.json`, create the
/// (paused) domain in the kernel, set up its cgroup, persist state and write any
/// `--pid-file`. Returns the persisted [`State`].
fn create_from_bundle(
    root: &str,
    flags: &HashMap<String, String>,
    id: &str,
    bundle: &Path,
) -> State {
    if state_path(root, id).exists() {
        die(format!("container {id:?} already exists"));
    }

    let raw = fs::read_to_string(bundle.join("config.json"))
        .unwrap_or_else(|e| die(format!("reading config.json: {e}")));
    let cfg = parse_config(&raw).unwrap_or_else(|e| die(e.to_string()));
    let spec = config_to_spec(bundle, &cfg).unwrap_or_else(|e| die(e.to_string()));

    let dev = Device::open().unwrap_or_else(|e| die(format!("open /dev/krunc: {e}")));
    let (kid, pid) = dev.create(&spec).unwrap_or_else(|e| die(format!("create: {e}")));

    // cgroup placement (userspace configures; the kernel enforces).
    let cg = cgroup_config(&cfg);
    let cgroup_dir = match cgroup::Cgroup::create(id, &cg) {
        Ok(Some(c)) => {
            if let Err(e) = c.place(pid) {
                eprintln!("krunc: warning: cgroup placement: {e}");
            }
            Some(c.dir().to_string_lossy().into_owned())
        }
        Ok(None) => None,
        Err(e) => {
            eprintln!("krunc: warning: cgroup setup: {e}");
            None
        }
    };

    let st = State {
        oci_version: OCI_VERSION.to_string(),
        id: id.to_string(),
        status: "created".to_string(),
        pid,
        bundle: bundle.to_string_lossy().into_owned(),
        krunc_id: kid,
        cgroup: cgroup_dir,
    };
    save_state(root, &st);
    if let Some(pf) = flags.get("--pid-file") {
        let _ = fs::write(pf, pid.to_string());
    }
    st
}

/// `run` = `create` + `start` + wait-for-exit + `delete`, in one shot — the
/// ergonomic, `docker run`-like entry point. Two forms are accepted:
///
/// * `krunc run --bundle <dir> [<id>]` — one-shot over an existing OCI bundle
///   (the `runc run` semantics).
/// * `krunc run [--rootfs <dir> | --image <name> | <name>] [--] <cmd> [args…]` —
///   synthesize a hardened bundle around an extracted rootfs and run `<cmd>`
///   inside it (the `docker run <image> <cmd>` semantics). `<name>` is resolved
///   under `$KRUNC_IMAGES` (default `/images`).
fn do_run(root: &str, flags: &HashMap<String, String>, args: &[String]) {
    let keep = flags.contains_key("--keep");
    let terminal = flags.contains_key("-t")
        || flags.contains_key("--terminal")
        || flags.contains_key("--tty");

    if flags.contains_key("--bundle") {
        let bundle = bundle_path(flags);
        let id = args.first().cloned().unwrap_or_else(gen_id);
        run_lifecycle(root, flags, &id, &bundle, None, keep);
        return;
    }

    // docker-like: resolve a rootfs image and a command to run inside it.
    let (rootfs, cmd): (PathBuf, Vec<String>) = if let Some(r) = flags.get("--rootfs") {
        (canon_dir("rootfs", r), args.to_vec())
    } else if let Some(name) = flags.get("--image") {
        (image_dir(name), args.to_vec())
    } else {
        let name = args
            .first()
            .unwrap_or_else(|| die("usage: run [--image <name>|--rootfs <dir>|<name>] <cmd> [args…]"));
        (image_dir(name), args[1..].to_vec())
    };
    let cmd = if cmd.is_empty() { vec!["/bin/sh".to_string()] } else { cmd };
    let cmd = resolve_cmd(&rootfs, cmd);
    ensure_mountpoints(&rootfs);
    let id = flags.get("--name").cloned().unwrap_or_else(gen_id);

    let tmp = std::env::temp_dir().join(format!("krunc-bundle-{id}"));
    fs::create_dir_all(&tmp).unwrap_or_else(|e| die(format!("mkdir bundle: {e}")));
    let cfg = synth_config(&rootfs.to_string_lossy(), &cmd, &id, terminal);
    fs::write(tmp.join("config.json"), cfg).unwrap_or_else(|e| die(format!("write config: {e}")));

    run_lifecycle(root, flags, &id, &tmp, Some(tmp.clone()), keep);
}

/// create → start → wait → (delete + cleanup). `tmp_bundle`, if set, is a
/// synthesized bundle dir removed on exit. Exits the process with the
/// container's own exit status (like `docker run` without `-d`).
fn run_lifecycle(
    root: &str,
    flags: &HashMap<String, String>,
    id: &str,
    bundle: &Path,
    tmp_bundle: Option<PathBuf>,
    keep: bool,
) {
    let mut st = create_from_bundle(root, flags, id, bundle);
    let dev = Device::open().unwrap_or_else(|e| die(format!("open: {e}")));
    dev.start(st.krunc_id).unwrap_or_else(|e| die(format!("start: {e}")));
    st.status = "running".to_string();
    save_state(root, &st);

    let code = wait_for_exit(&dev, st.pid, st.krunc_id);

    if !keep {
        let _ = dev.delete(st.krunc_id);
        if let Some(cg) = &st.cgroup {
            cgroup::remove(Path::new(cg));
        }
        let _ = fs::remove_dir_all(state_dir(root, &st.id));
    }
    if let Some(tmp) = tmp_bundle {
        let _ = fs::remove_dir_all(tmp);
    }
    exit(code);
}

/// Block until the container's init exits, returning its exit code.
///
/// The init is our direct child (the create ioctl `clone`d it in this process's
/// context), so we `waitpid` it: this reaps the zombie — without which the
/// kernel's liveness check (`kill(pid, 0)`) would keep reporting it *running* —
/// and yields the true exit status. `__WALL` is used because a freshly-`exec`d
/// kernel-thread child may not carry the `SIGCHLD` exit signal. If it turns out
/// not to be our child (`ECHILD`), fall back to polling kernel state.
fn wait_for_exit(dev: &Device, pid: i32, kid: u64) -> i32 {
    loop {
        let mut status: libc::c_int = 0;
        // SAFETY: `status` is a valid writable int; `waitpid` only writes it.
        let r = unsafe { libc::waitpid(pid, &mut status, libc::__WALL) };
        if r == pid {
            if libc::WIFEXITED(status) {
                return libc::WEXITSTATUS(status);
            }
            if libc::WIFSIGNALED(status) {
                return 128 + libc::WTERMSIG(status);
            }
            return 0;
        }
        match std::io::Error::last_os_error().raw_os_error() {
            Some(libc::EINTR) => continue,
            _ => break, // ECHILD/other: not reapable here — poll instead.
        }
    }
    wait_stopped(dev, kid);
    0
}

/// Block until the kernel reports the container Stopped (fallback path).
fn wait_stopped(dev: &Device, kid: u64) {
    loop {
        match dev.state(kid) {
            Ok((KState::Stopped, _)) => return,
            Ok(_) => std::thread::sleep(std::time::Duration::from_millis(100)),
            Err(_) => return,
        }
    }
}

/// Resolve a docker-style image name to an extracted rootfs directory under
/// `$KRUNC_IMAGES` (default `/images`).
fn image_dir(name: &str) -> PathBuf {
    let base = std::env::var("KRUNC_IMAGES").unwrap_or_else(|_| "/images".to_string());
    let dir = Path::new(&base).join(name);
    fs::canonicalize(&dir)
        .unwrap_or_else(|e| die(format!("image {name:?} ({}): {e}", dir.display())))
}

fn canon_dir(what: &str, p: &str) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|e| die(format!("{what} {p:?}: {e}")))
}

/// Resolve `argv[0]` against the image like a shell `PATH` lookup would: a name
/// without a slash (e.g. `echo`) is rewritten to its absolute in-container path
/// (e.g. `/bin/echo`) because the kernel's `execve` takes an absolute path. Left
/// unchanged if already absolute or not found (so `execve` reports it).
fn resolve_cmd(rootfs: &Path, mut args: Vec<String>) -> Vec<String> {
    let Some(prog) = args.first().cloned() else {
        return vec!["/bin/sh".to_string()];
    };
    if prog.contains('/') {
        return args;
    }
    for dir in ["/bin", "/usr/bin", "/sbin", "/usr/sbin", "/usr/local/bin", "/usr/local/sbin"] {
        if rootfs.join(dir.trim_start_matches('/')).join(&prog).exists() {
            args[0] = format!("{dir}/{prog}");
            return args;
        }
    }
    args
}

/// Create the standard mountpoints the synthesized config mounts over, so a
/// minimal image (which may ship without `/proc`, `/sys`, …) still works — the
/// same courtesy a higher-level runtime extends when materializing a rootfs.
fn ensure_mountpoints(rootfs: &Path) {
    for d in ["proc", "sys", "tmp", "dev"] {
        let _ = fs::create_dir_all(rootfs.join(d));
    }
}

/// A short, unique container id (used when `--name`/`<id>` is omitted).
fn gen_id() -> String {
    let ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("krunc-{:08x}", (ns as u64) & 0xffff_ffff)
}

/// Build a hardened OCI `config.json` around `rootfs_abs`, running `args` as
/// container PID 1. Mirrors `examples/bundle/config.json`: dropped capabilities,
/// `noNewPrivileges`, a private namespace set, pid/memory cgroup caps, masked &
/// read-only `/proc` paths, and a seccomp policy that kills module-loading and
/// kexec attempts.
fn synth_config(rootfs_abs: &str, args: &[String], hostname: &str, terminal: bool) -> String {
    let args_json = args
        .iter()
        .map(|a| serde_json::to_string(a).expect("encode arg"))
        .collect::<Vec<_>>()
        .join(", ");
    let host_json = serde_json::to_string(hostname).expect("encode host");
    let root_json = serde_json::to_string(rootfs_abs).expect("encode root");
    format!(
        r#"{{
  "ociVersion": "1.0.2-dev",
  "hostname": {host_json},
  "process": {{
    "terminal": {terminal},
    "user": {{ "uid": 0, "gid": 0 }},
    "args": [{args_json}],
    "env": [
      "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
      "HOME=/root",
      "TERM=xterm",
      "container=krunc"
    ],
    "cwd": "/",
    "noNewPrivileges": true,
    "capabilities": {{
      "bounding": [], "effective": [], "permitted": [],
      "inheritable": [], "ambient": []
    }}
  }},
  "root": {{ "path": {root_json}, "readonly": false }},
  "linux": {{
    "namespaces": [
      {{ "type": "pid" }}, {{ "type": "mount" }}, {{ "type": "uts" }},
      {{ "type": "ipc" }}, {{ "type": "network" }}
    ],
    "cgroupsPath": "krunc/{hostname}",
    "resources": {{
      "pids": {{ "limit": 256 }},
      "memory": {{ "limit": 268435456 }}
    }},
    "maskedPaths": ["/proc/kcore", "/proc/sysrq-trigger"],
    "readonlyPaths": ["/proc/sys"],
    "seccomp": {{
      "defaultAction": "SCMP_ACT_ALLOW",
      "architectures": ["SCMP_ARCH_X86_64"],
      "syscalls": [
        {{
          "names": ["init_module", "finit_module", "delete_module",
                    "kexec_load", "kexec_file_load"],
          "action": "SCMP_ACT_KILL_PROCESS"
        }}
      ]
    }}
  }},
  "mounts": [
    {{ "destination": "/proc", "type": "proc", "source": "proc" }},
    {{ "destination": "/sys", "type": "sysfs", "source": "sysfs",
      "options": ["nosuid", "nodev", "noexec", "ro"] }},
    {{ "destination": "/tmp", "type": "tmpfs", "source": "tmpfs",
      "options": ["nosuid", "nodev", "noexec"] }}
  ]
}}"#
    )
}

fn do_start(root: &str, args: &[String]) {
    let id = args.first().unwrap_or_else(|| die("usage: start <id>"));
    let mut st = load_state(root, id);
    let dev = Device::open().unwrap_or_else(|e| die(format!("open: {e}")));
    dev.start(st.krunc_id).unwrap_or_else(|e| die(format!("start: {e}")));
    st.status = "running".to_string();
    save_state(root, &st);
}

fn do_state(root: &str, args: &[String]) {
    let id = args.first().unwrap_or_else(|| die("usage: state <id>"));
    let mut st = load_state(root, id);
    let dev = Device::open().unwrap_or_else(|e| die(format!("open: {e}")));
    if let Ok((s, pid)) = dev.state(st.krunc_id) {
        st.status = status_str(s).to_string();
        st.pid = pid;
        save_state(root, &st);
    }
    println!("{}", serde_json::to_string_pretty(&st).expect("serialize"));
}

fn do_kill(root: &str, args: &[String]) {
    let id = args.first().unwrap_or_else(|| die("usage: kill <id> [signal]"));
    let st = load_state(root, id);
    let sig = args.get(1).map(|s| parse_signal(s)).unwrap_or(9);
    let dev = Device::open().unwrap_or_else(|e| die(format!("open: {e}")));
    dev.kill(st.krunc_id, sig).unwrap_or_else(|e| die(format!("kill: {e}")));
}

fn do_delete(root: &str, flags: &HashMap<String, String>, args: &[String]) {
    let id = args.first().unwrap_or_else(|| die("usage: delete <id>"));
    let path = state_path(root, id);
    if !path.exists() {
        if flags.contains_key("--force") || flags.contains_key("-f") {
            return;
        }
        die(format!("container {id:?} does not exist"));
    }
    let st = load_state(root, id);
    if let Ok(dev) = Device::open() {
        let _ = dev.delete(st.krunc_id);
    }
    if let Some(cg) = &st.cgroup {
        cgroup::remove(Path::new(cg));
    }
    let _ = fs::remove_dir_all(state_dir(root, id));
}

fn do_list(root: &str) {
    println!("{:<20} {:<10} {:<8} BUNDLE", "ID", "STATUS", "PID");
    let Ok(entries) = fs::read_dir(root) else { return };
    for e in entries.flatten() {
        if !e.path().is_dir() {
            continue;
        }
        let p = e.path().join("state.json");
        if let Ok(raw) = fs::read(&p) {
            if let Ok(st) = serde_json::from_slice::<State>(&raw) {
                println!("{:<20} {:<10} {:<8} {}", st.id, st.status, st.pid, st.bundle);
            }
        }
    }
}

fn parse_signal(s: &str) -> i32 {
    let s = s.strip_prefix("SIG").unwrap_or(s);
    match s.to_uppercase().as_str() {
        "KILL" => 9,
        "TERM" => 15,
        "INT" => 2,
        "HUP" => 1,
        "QUIT" => 3,
        "STOP" => 19,
        other => other.parse().unwrap_or(9),
    }
}

fn print_version() {
    println!("runc version {VERSION}");
    println!("commit: krunc-poc");
    println!("spec: {OCI_VERSION}");
}
