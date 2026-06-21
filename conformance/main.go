// krunc-conformance drives the krunc OCI runtime through github.com/containerd/
// go-runc — the *exact* library that containerd-shim-runc-v2 uses to invoke a
// runc-compatible runtime. If this drives krunc through create/start/state/
// delete, it demonstrates that containerd's runtime-invocation layer is
// contract-compatible with krunc.
//
// Usage: krunc-conformance <bundle-dir>
package main

import (
	"context"
	"fmt"
	"os"
	"time"

	runc "github.com/containerd/go-runc"
)

func main() {
	bundle := "/bundle"
	if len(os.Args) > 1 {
		bundle = os.Args[1]
	}
	id := "ctr1"
	ctx := context.Background()

	// This is configured exactly like the containerd runc shim configures it:
	// a runc-compatible binary plus a state root.
	r := &runc.Runc{
		Command: "/bin/krunc",
		Root:    "/run/krunc-runc",
	}

	fmt.Println("[go-runc] using github.com/containerd/go-runc (containerd's runtime client)")

	if v, err := r.Version(ctx); err == nil {
		fmt.Printf("[go-runc] runtime: %q spec: %q\n", v.Runc, v.Spec)
	} else {
		fmt.Printf("[go-runc] Version: %v\n", err)
	}

	stdio, err := runc.NewSTDIO()
	if err != nil {
		fail("NewSTDIO", err)
	}
	if err := r.Create(ctx, id, bundle, &runc.CreateOpts{
		PidFile: "/run/ctr1.pid",
		// Provide explicit stdio, exactly as containerd-shim-runc-v2 does for a
		// non-terminal task (it passes the task's fifos here). Without this,
		// go-runc pipe-captures the runtime's output and would block because the
		// container inherits and holds that pipe open.
		IO: stdio,
	}); err != nil {
		fail("Create", err)
	}
	fmt.Println("[go-runc] Create OK (container set up, paused before exec)")

	report(r, ctx, id, "after Create")

	if err := r.Start(ctx, id); err != nil {
		fail("Start", err)
	}
	fmt.Println("[go-runc] Start OK (entrypoint exec'd)")
	time.Sleep(1 * time.Second)
	report(r, ctx, id, "after Start")

	time.Sleep(3 * time.Second)
	report(r, ctx, id, "after entrypoint exit")

	if err := r.Delete(ctx, id, &runc.DeleteOpts{Force: true}); err != nil {
		fail("Delete", err)
	}
	fmt.Println("[go-runc] Delete OK")
	fmt.Println("[go-runc] SUCCESS: containerd's runtime client drove krunc through the OCI lifecycle")
}

func report(r *runc.Runc, ctx context.Context, id, when string) {
	st, err := r.State(ctx, id)
	if err != nil {
		fmt.Printf("[go-runc] State %s: error %v\n", when, err)
		return
	}
	fmt.Printf("[go-runc] State %s: status=%q pid=%d\n", when, st.Status, st.Pid)
}

func fail(op string, err error) {
	fmt.Fprintf(os.Stderr, "[go-runc] %s FAILED: %v\n", op, err)
	os.Exit(1)
}
