//! `krunc` — a runc/OCI-compatible CLI that drives the krunc kernel domain.
//!
//! It reads an OCI bundle's `config.json`, translates it to a validated
//! [`krunc_abi::DomainSpec`] (via `krunc-oci`), and issues the lifecycle ioctls
//! to `/dev/krunc`. Per-id state is persisted under `--root` (default
//! `/run/krunc`) like runc, so each subcommand is a separate process.

mod device;

use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::exit;

use serde::{Deserialize, Serialize};

use device::{Device, KState};
use krunc_oci::{config_to_spec, parse_config};

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
    ];
    let mut flags = HashMap::new();
    let mut pos = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let a = &args[i];
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
    let bundle = flags
        .get("--bundle")
        .cloned()
        .unwrap_or_else(|| ".".to_string());
    let bundle = fs::canonicalize(&bundle)
        .unwrap_or_else(|e| die(format!("bundle {bundle:?}: {e}")));

    if state_path(root, id).exists() {
        die(format!("container {id:?} already exists"));
    }

    let raw = fs::read_to_string(bundle.join("config.json"))
        .unwrap_or_else(|e| die(format!("reading config.json: {e}")));
    let cfg = parse_config(&raw).unwrap_or_else(|e| die(e.to_string()));
    let spec = config_to_spec(&bundle, &cfg).unwrap_or_else(|e| die(e.to_string()));

    let dev = Device::open().unwrap_or_else(|e| die(format!("open /dev/krunc: {e}")));
    let (kid, pid) = dev.create(&spec).unwrap_or_else(|e| die(format!("create: {e}")));

    save_state(
        root,
        &State {
            oci_version: OCI_VERSION.to_string(),
            id: id.clone(),
            status: "created".to_string(),
            pid,
            bundle: bundle.to_string_lossy().into_owned(),
            krunc_id: kid,
        },
    );
    if let Some(pf) = flags.get("--pid-file") {
        let _ = fs::write(pf, pid.to_string());
    }
    eprintln!("created {id} (pid {pid}, krunc id {kid})");
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
