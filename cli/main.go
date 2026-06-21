// krunc - a minimal runc/OCI-compatible runtime CLI backed by the krunc kernel
// module. It implements the subset of the OCI runtime command surface that a
// higher-level runtime (e.g. containerd via containerd-shim-runc-v2) drives:
//
//	krunc [globals] create --bundle <dir> [--pid-file <f>] <id>
//	krunc [globals] start  <id>
//	krunc [globals] state  <id>
//	krunc [globals] kill   <id> <signal>
//	krunc [globals] delete [--force] <id>
//	krunc [globals] list
//	krunc --version
//
// It reads the OCI bundle's config.json, translates the subset it supports into
// a krunc kernel spec, and drives the kernel module's ioctl lifecycle
// (create=paused, start=exec, state, kill, delete) over /dev/krunc. Per-id
// state is persisted under --root (default /run/krunc) like runc.
//
// Supported config.json subset: process.args, process.env, root.path, hostname,
// linux.namespaces (pid/mount/uts/ipc/network). Ignored (documented): cgroups,
// mounts, capabilities, seccomp, rlimits, devices, hooks, user mapping.
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

const (
	version    = "1.1.0-krunc"
	ociVersion = "1.0.2-dev"
	device     = "/dev/krunc"

	nrCreate = 1
	nrStart  = 2
	nrState  = 3
	nrKill   = 4
	nrDelete = 5
)

// kruncCmd mirrors the kernel's #[repr(C)] KruncCmd (32 bytes, no padding).
type kruncCmd struct {
	SpecPtr uint64
	ID      uint64
	SpecLen uint32
	Pid     int32
	Sig     int32
	State   uint32
}

func iocNR(nr uintptr) uintptr {
	// _IOC(dir=READ|WRITE, type='k', nr, size=sizeof(kruncCmd)). The kernel
	// matches on the nr only, so size/dir need not match exactly.
	const size = 32
	return (3 << 30) | (size << 16) | (uintptr('k') << 8) | nr
}

func ioctl(fd uintptr, nr uintptr, c *kruncCmd) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, iocNR(nr), uintptr(unsafe.Pointer(c)))
	if errno != 0 {
		return errno
	}
	return nil
}

// ---- OCI types (subset) ----

type ociSpec struct {
	OCIVersion string `json:"ociVersion"`
	Hostname   string `json:"hostname"`
	Process    *struct {
		Terminal bool     `json:"terminal"`
		Args     []string `json:"args"`
		Env      []string `json:"env"`
		Cwd      string   `json:"cwd"`
	} `json:"process"`
	Root *struct {
		Path string `json:"path"`
	} `json:"root"`
	Linux *struct {
		Namespaces []struct {
			Type string `json:"type"`
		} `json:"namespaces"`
	} `json:"linux"`
	Annotations map[string]string `json:"annotations"`
}

// containerState is what we persist and what `state` prints (OCI state schema).
type containerState struct {
	OCIVersion  string            `json:"ociVersion"`
	ID          string            `json:"id"`
	Status      string            `json:"status"`
	Pid         int               `json:"pid"`
	Bundle      string            `json:"bundle"`
	KernelID    uint64            `json:"kruncId"`
	Created     string            `json:"created,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

func die(format string, a ...interface{}) {
	fmt.Fprintf(os.Stderr, "krunc: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	flags, pos := parseArgs(os.Args[1:])
	if _, ok := flags["--version"]; ok || (len(pos) > 0 && pos[0] == "version") {
		printVersion()
		return
	}
	if len(pos) == 0 {
		die("no command (try: create/start/state/kill/delete/list)")
	}
	root := flags["--root"]
	if root == "" {
		root = "/run/krunc"
	}
	cmd, args := pos[0], pos[1:]

	switch cmd {
	case "create":
		doCreate(root, flags, args)
	case "start":
		doStart(root, args)
	case "state":
		doState(root, args)
	case "kill":
		doKill(root, flags, args)
	case "delete":
		doDelete(root, flags, args)
	case "list":
		doList(root)
	case "features":
		printFeatures()
	default:
		die("unknown command %q", cmd)
	}
}

// parseArgs does a lenient single pass: known value-taking flags consume the
// next token; everything else "--x" is boolean; non-flags are positionals.
func parseArgs(args []string) (map[string]string, []string) {
	valued := map[string]bool{
		"--root": true, "--log": true, "--log-format": true, "--criu": true,
		"--rootless": true, "--bundle": true, "-b": true, "--pid-file": true,
		"--console-socket": true, "--preserve-fds": true, "--process": true,
		"--pid": true,
	}
	flags := map[string]string{}
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if eq := strings.IndexByte(a, '='); eq >= 0 {
				flags[a[:eq]] = a[eq+1:]
			} else if valued[a] && i+1 < len(args) {
				flags[a] = args[i+1]
				i++
			} else {
				flags[a] = "true"
			}
		} else {
			pos = append(pos, a)
		}
	}
	if v, ok := flags["-b"]; ok {
		flags["--bundle"] = v
	}
	return flags, pos
}

func openDevice() *os.File {
	f, err := os.OpenFile(device, os.O_RDWR, 0)
	if err != nil {
		die("opening %s: %v (is the krunc module loaded?)", device, err)
	}
	return f
}

func stateDir(root, id string) string  { return filepath.Join(root, id) }
func statePath(root, id string) string { return filepath.Join(root, id, "state.json") }

func loadState(root, id string) *containerState {
	b, err := os.ReadFile(statePath(root, id))
	if err != nil {
		die("container %q does not exist", id)
	}
	var s containerState
	if err := json.Unmarshal(b, &s); err != nil {
		die("corrupt state for %q: %v", id, err)
	}
	return &s
}

func saveState(root string, s *containerState) {
	if err := os.MkdirAll(stateDir(root, s.ID), 0700); err != nil {
		die("mkdir state: %v", err)
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	if err := os.WriteFile(statePath(root, s.ID), b, 0600); err != nil {
		die("write state: %v", err)
	}
}

// buildSpec turns an OCI bundle into the krunc kernel spec (newline key=value).
func buildSpec(bundle string, s *ociSpec) string {
	if s.Process == nil || len(s.Process.Args) == 0 {
		die("config.json: process.args is required")
	}
	if s.Root == nil || s.Root.Path == "" {
		die("config.json: root.path is required")
	}
	rootfs := s.Root.Path
	if !filepath.IsAbs(rootfs) {
		rootfs = filepath.Join(bundle, rootfs)
	}
	host := s.Hostname
	if host == "" {
		host = "krunc"
	}
	var b strings.Builder
	fmt.Fprintf(&b, "rootfs=%s\n", rootfs)
	fmt.Fprintf(&b, "host=%s\n", host)
	for _, a := range s.Process.Args {
		fmt.Fprintf(&b, "arg=%s\n", a)
	}
	for _, e := range s.Process.Env {
		fmt.Fprintf(&b, "env=%s\n", e)
	}
	var ns []string
	if s.Linux != nil {
		for _, n := range s.Linux.Namespaces {
			switch n.Type {
			case "pid", "mount", "uts", "ipc", "network":
				ns = append(ns, n.Type)
			}
		}
	}
	if len(ns) > 0 {
		fmt.Fprintf(&b, "ns=%s\n", strings.Join(ns, ","))
	}
	return b.String()
}

func doCreate(root string, flags map[string]string, args []string) {
	if len(args) < 1 {
		die("usage: create --bundle <dir> <id>")
	}
	id := args[0]
	bundle := flags["--bundle"]
	if bundle == "" {
		bundle, _ = os.Getwd()
	}
	bundle, _ = filepath.Abs(bundle)
	if _, err := os.Stat(statePath(root, id)); err == nil {
		die("container %q already exists", id)
	}

	raw, err := os.ReadFile(filepath.Join(bundle, "config.json"))
	if err != nil {
		die("reading bundle config.json: %v", err)
	}
	var spec ociSpec
	if err := json.Unmarshal(raw, &spec); err != nil {
		die("parsing config.json: %v", err)
	}
	specText := []byte(buildSpec(bundle, &spec))

	f := openDevice()
	defer f.Close()
	c := kruncCmd{
		SpecPtr: uint64(uintptr(unsafe.Pointer(&specText[0]))),
		SpecLen: uint32(len(specText)),
	}
	err = ioctl(f.Fd(), nrCreate, &c)
	runtime.KeepAlive(specText)
	if err != nil {
		die("create ioctl: %v", err)
	}

	st := &containerState{
		OCIVersion:  ociVersion,
		ID:          id,
		Status:      "created",
		Pid:         int(c.Pid),
		Bundle:      bundle,
		KernelID:    c.ID,
		Created:     time.Now().UTC().Format(time.RFC3339Nano),
		Annotations: spec.Annotations,
	}
	saveState(root, st)
	if pf := flags["--pid-file"]; pf != "" {
		os.WriteFile(pf, []byte(strconv.Itoa(int(c.Pid))), 0644)
	}
	fmt.Printf("created %s (pid %d, krunc id %d)\n", id, c.Pid, c.ID)
}

func doStart(root string, args []string) {
	if len(args) < 1 {
		die("usage: start <id>")
	}
	st := loadState(root, args[0])
	f := openDevice()
	defer f.Close()
	c := kruncCmd{ID: st.KernelID}
	if err := ioctl(f.Fd(), nrStart, &c); err != nil {
		die("start ioctl: %v", err)
	}
	st.Status = "running"
	saveState(root, st)
}

func doState(root string, args []string) {
	if len(args) < 1 {
		die("usage: state <id>")
	}
	st := loadState(root, args[0])
	f := openDevice()
	defer f.Close()
	c := kruncCmd{ID: st.KernelID}
	if err := ioctl(f.Fd(), nrState, &c); err == nil {
		switch c.State {
		case 0:
			st.Status = "created"
		case 1:
			st.Status = "running"
		default:
			st.Status = "stopped"
		}
		st.Pid = int(c.Pid)
		saveState(root, st)
	}
	b, _ := json.MarshalIndent(st, "", "  ")
	fmt.Println(string(b))
}

func doKill(root string, flags map[string]string, args []string) {
	if len(args) < 1 {
		die("usage: kill <id> [signal]")
	}
	st := loadState(root, args[0])
	sig := int32(9)
	if len(args) >= 2 {
		sig = parseSignal(args[1])
	}
	f := openDevice()
	defer f.Close()
	c := kruncCmd{ID: st.KernelID, Sig: sig}
	if err := ioctl(f.Fd(), nrKill, &c); err != nil {
		die("kill ioctl: %v", err)
	}
}

func doDelete(root string, flags map[string]string, args []string) {
	if len(args) < 1 {
		die("usage: delete <id>")
	}
	id := args[0]
	b, err := os.ReadFile(statePath(root, id))
	if err != nil {
		if _, force := flags["--force"]; force {
			return
		}
		die("container %q does not exist", id)
	}
	var st containerState
	json.Unmarshal(b, &st)
	f := openDevice()
	c := kruncCmd{ID: st.KernelID}
	ioctl(f.Fd(), nrDelete, &c)
	f.Close()
	os.RemoveAll(stateDir(root, id))
}

func doList(root string) {
	entries, _ := os.ReadDir(root)
	fmt.Printf("%-20s %-10s %-8s %s\n", "ID", "STATUS", "PID", "BUNDLE")
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		b, err := os.ReadFile(statePath(root, e.Name()))
		if err != nil {
			continue
		}
		var st containerState
		if json.Unmarshal(b, &st) != nil {
			continue
		}
		fmt.Printf("%-20s %-10s %-8d %s\n", st.ID, st.Status, st.Pid, st.Bundle)
	}
}

func parseSignal(s string) int32 {
	s = strings.TrimPrefix(strings.ToUpper(s), "SIG")
	switch s {
	case "KILL":
		return 9
	case "TERM":
		return 15
	case "INT":
		return 2
	case "HUP":
		return 1
	case "QUIT":
		return 3
	case "STOP":
		return 19
	}
	if n, err := strconv.Atoi(s); err == nil {
		return int32(n)
	}
	return 9
}

func printVersion() {
	fmt.Printf("runc version %s\n", version)
	fmt.Printf("commit: krunc-poc\n")
	fmt.Printf("spec: %s\n", ociVersion)
	fmt.Printf("go: %s\n", runtime.Version())
}

func printFeatures() {
	// Minimal so containerd's feature probe does not choke.
	fmt.Println(`{"ociVersionMin":"1.0.0","ociVersionMax":"1.0.2-dev"}`)
}
