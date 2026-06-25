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
use krunc_oci::{cgroup_config, config_to_spec, parse_config, OciConfig};

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
    /// OCI state annotations. krunc records the init's exit code or terminating
    /// signal here (`org.krunc.exitCode` / `org.krunc.exitSignal`) once stopped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    annotations: Option<std::collections::BTreeMap<String, String>>,
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
        "__decode-check" => do_decode_check(),
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
    let mut cfg = parse_config(&raw).unwrap_or_else(|e| die(e.to_string()));
    prepare_rootfs(bundle, &mut cfg);
    let spec = config_to_spec(bundle, &cfg).unwrap_or_else(|e| die(e.to_string()));

    let dev = Device::open().unwrap_or_else(|e| die(format!("open /dev/krunc: {e}")));
    let (kid, pid) = dev.create(&spec).unwrap_or_else(|e| die(format!("create: {e}")));

    // Apply user-namespace ID mappings (linux.uid/gidMappings) from userspace: the
    // kernel module creates the user namespace (CLONE_NEWUSER) but cannot write the
    // child's procfs uid_map (kernel_write needs write_iter, which uid_map lacks),
    // so — exactly as runc does — the CLI writes /proc/<pid>/{uid,gid}_map here. The
    // CLI is privileged (root in init_user_ns), so range maps are permitted; the
    // container is paused before it applies its creds, so the maps are in place in
    // time. If this fails we must not run with unmapped credentials: tear down.
    if !spec.uid_maps.is_empty() || !spec.gid_maps.is_empty() {
        if let Err(e) = write_id_maps(pid, &spec.uid_maps, &spec.gid_maps) {
            let _ = dev.delete(kid);
            die(format!("applying user-namespace ID maps: {e}"));
        }
    }

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
        annotations: None,
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
            Ok((KState::Stopped, _, _)) => return,
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

/// Prepare an extracted rootfs the way a higher-level runtime (runc) does before
/// the kernel enters it, so configs generated by containerd/nerdctl — or our own
/// synthesized ones — run unmodified:
///
/// * create the mount destination directories (a minimal image may ship without
///   `/proc`, `/sys`, `/dev`, …, which would make the in-kernel mounts fail), and
/// * resolve `process.args[0]` against the container `PATH` to an absolute path
///   (the kernel's `execve` takes an absolute path; it does no `PATH` search).
///
/// Operates on the rootfs in the host mount namespace (where containerd has
/// already materialized it), mutating the parsed config in place.
fn prepare_rootfs(bundle: &Path, cfg: &mut OciConfig) {
    let Some(root) = cfg.root.as_ref() else { return };
    let rp = Path::new(&root.path);
    let rootfs = if rp.is_absolute() { rp.to_path_buf() } else { bundle.join(rp) };

    for d in ["proc", "sys", "dev", "tmp"] {
        let _ = fs::create_dir_all(rootfs.join(d));
    }
    for m in &cfg.mounts {
        let dest = m.destination.trim_start_matches('/');
        if !dest.is_empty() {
            let _ = fs::create_dir_all(rootfs.join(dest));
        }
    }

    if let Some(proc) = cfg.process.as_mut() {
        if let Some(arg0) = proc.args.first().cloned() {
            if !arg0.contains('/') {
                let dirs: Vec<String> = proc
                    .env
                    .iter()
                    .find_map(|e| e.strip_prefix("PATH="))
                    .map(|p| p.split(':').map(String::from).collect())
                    .unwrap_or_else(|| {
                        ["/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
                            .iter()
                            .map(|s| s.to_string())
                            .collect()
                    });
                for d in dirs {
                    let d = d.trim_end_matches('/');
                    if !d.is_empty() && rootfs.join(d.trim_start_matches('/')).join(&arg0).exists() {
                        proc.args[0] = format!("{d}/{arg0}");
                        break;
                    }
                }
            }
        }
    }
}

/// Write a container's user-namespace ID maps from userspace (the privileged CLI
/// in the parent user namespace). Each `/proc/<pid>/{uid,gid}_map` accepts the
/// whole map in a single write; lines are `"<containerID> <hostID> <size>"`.
fn write_id_maps(
    pid: i32,
    uid_maps: &[krunc_abi::IdMap],
    gid_maps: &[krunc_abi::IdMap],
) -> std::io::Result<()> {
    fn render(maps: &[krunc_abi::IdMap]) -> String {
        maps.iter()
            .map(|m| format!("{} {} {}", m.container_id, m.host_id, m.size))
            .collect::<Vec<_>>()
            .join("\n")
    }
    if !uid_maps.is_empty() {
        fs::write(format!("/proc/{pid}/uid_map"), render(uid_maps))?;
    }
    if !gid_maps.is_empty() {
        fs::write(format!("/proc/{pid}/gid_map"), render(gid_maps))?;
    }
    Ok(())
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
/// `noNewPrivileges`, a private namespace set, pid/memory cgroup caps, and
/// masked & read-only `/proc` paths.
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
    "readonlyPaths": ["/proc/sys"]
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
    if let Ok((s, pid, exit_status)) = dev.state(st.krunc_id) {
        st.status = status_str(s).to_string();
        st.pid = pid;
        if s == KState::Stopped {
            st.annotations = exit_annotations(exit_status);
        }
        save_state(root, &st);
    }
    println!("{}", serde_json::to_string_pretty(&st).expect("serialize"));
}

/// Decode a wait(2)-style status word into OCI state annotations recording how
/// the container's init terminated. A `0` word (clean exit, or an exit that was
/// reaped before krunc could observe it) is reported as exit code 0.
fn exit_annotations(status: i32) -> Option<std::collections::BTreeMap<String, String>> {
    let mut m = std::collections::BTreeMap::new();
    if libc::WIFSIGNALED(status) {
        m.insert(
            "org.krunc.exitSignal".to_string(),
            libc::WTERMSIG(status).to_string(),
        );
    } else {
        m.insert(
            "org.krunc.exitCode".to_string(),
            libc::WEXITSTATUS(status).to_string(),
        );
    }
    Some(m)
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

/// Self-test (used by the QEMU demo): drive malformed binary specs straight at
/// the kernel's `decode_spec` via the create ioctl and confirm each is rejected
/// gracefully — the kernel must never panic, over-read, or accept a malformed
/// blob. This verifies the real untrusted boundary (the userspace `krunc-abi`
/// decoder is fuzz-tested separately). The happy path (a valid blob is accepted)
/// is covered by the normal create demo, so here every case must be rejected.
fn do_decode_check() {
    use krunc_abi::{DomainSpec, Op};

    let dev = Device::open().unwrap_or_else(|e| die(format!("open /dev/krunc: {e}")));
    let base = DomainSpec {
        rootfs: "/bundle/rootfs".into(),
        argv: vec!["/bin/sh".into()],
        ..Default::default()
    }
    .encode(Op::Create)
    .expect("encode base spec");

    let mut cases: Vec<(&str, Vec<u8>)> = vec![
        ("empty", Vec::new()),
        ("bad-magic", {
            let mut b = base.clone();
            b[0] ^= 0xff;
            b
        }),
        ("truncated", base[..base.len() / 2].to_vec()),
        ("trailing-byte", {
            let mut b = base.clone();
            b.push(0);
            b
        }),
    ];
    // Section length field (offset 20..24) set to u32::MAX: an over-read attempt.
    if base.len() >= 24 {
        let mut b = base.clone();
        b[20..24].copy_from_slice(&u32::MAX.to_le_bytes());
        cases.push(("huge-section-len", b));
    }
    // Duplicate the first section (and bump the section count): the kernel must
    // reject a repeated tag rather than silently take the second value.
    if base.len() >= 24 {
        let seclen = u32::from_le_bytes([base[20], base[21], base[22], base[23]]) as usize;
        if let Some(end) = 24usize.checked_add(seclen) {
            if end <= base.len() {
                let mut b = base.clone();
                let count = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
                let first = b[16..end].to_vec();
                b[12..16].copy_from_slice(&count.wrapping_add(1).to_le_bytes());
                b.extend_from_slice(&first);
                cases.push(("duplicate-section", b));
            }
        }
    }

    let mut failures = 0;
    for (name, blob) in &cases {
        match dev.create_raw(blob) {
            Err(_) => println!("[decode-check]   {name}: rejected (ok)"),
            Ok((id, _)) => {
                let _ = dev.delete(id); // clean up the unexpected container
                eprintln!("[decode-check]   {name}: ACCEPTED (FAIL)");
                failures += 1;
            }
        }
    }
    if failures == 0 {
        println!(
            "[decode-check] all {} malformed blobs rejected; kernel decoder is robust",
            cases.len()
        );
    } else {
        die(format!("[decode-check] {failures} malformed blob(s) accepted"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    #[test]
    fn synth_config_parses_under_strict_rules() {
        // `krunc run` synthesizes this config; it must satisfy the strict
        // (reject-unmodeled) translation rules so the docker-style path keeps
        // working. Exercised here because the QEMU demo drives `create` instead.
        let args = ["/bin/sh".to_string(), "-c".to_string(), "echo hi".to_string()];
        let json = synth_config("/img/rootfs", &args, "krunc-test", false);
        let cfg = parse_config(&json).expect("synth config must parse");
        let spec = config_to_spec(Path::new("/img"), &cfg).expect("synth config must translate");
        assert_eq!(spec.rootfs, "/img/rootfs");
        assert_eq!(spec.argv, args);
    }

    #[test]
    fn synth_config_with_terminal_is_rejected() {
        // process.terminal=true is rejected per spec (krunc allocates no PTY), so
        // `krunc run -t` must fail at translation rather than silently drop it.
        let args = ["/bin/sh".to_string()];
        let json = synth_config("/img/rootfs", &args, "krunc-test", true);
        let cfg = parse_config(&json).expect("synth config must parse");
        assert!(config_to_spec(Path::new("/img"), &cfg).is_err());
    }

    #[test]
    fn exit_annotations_decode_code_and_signal() {
        // A clean exit with code 42 → wait-status word (42 << 8). The CLI must
        // decode it into org.krunc.exitCode = 42 (and no exitSignal).
        let a = exit_annotations(42 << 8).expect("annotations");
        assert_eq!(a.get("org.krunc.exitCode").map(String::as_str), Some("42"));
        assert!(!a.contains_key("org.krunc.exitSignal"));

        // Termination by SIGKILL (9) → low 7 bits carry the signal. The CLI must
        // decode it into org.krunc.exitSignal = 9 (and no exitCode).
        let a = exit_annotations(9).expect("annotations");
        assert_eq!(a.get("org.krunc.exitSignal").map(String::as_str), Some("9"));
        assert!(!a.contains_key("org.krunc.exitCode"));

        // A zero word (clean exit 0, or an exit reaped before krunc saw it) is
        // reported as exit code 0.
        let a = exit_annotations(0).expect("annotations");
        assert_eq!(a.get("org.krunc.exitCode").map(String::as_str), Some("0"));
    }
}
