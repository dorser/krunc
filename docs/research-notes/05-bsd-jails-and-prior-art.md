Agent completed. agent_id: jails-priorart-research, agent_type: research, status: completed, description: Research BSD jails + Linux workload-object prior art, elapsed: 586s, total_turns: 0, duration: 497s

I now have sufficient primary sources across all four parts. Let me compile the comprehensive report.

---

# Prior Art Report: Toward a First-Class Linux "Workload / Security-Domain" Object

---

## SUMMARY

FreeBSD jails are a canonical example of a first-class kernel object for OS-level virtualization: a single `struct prison` anchors every process's identity, is immutable after attachment, propagates monotonically through `fork(2)`/`exec(2)` via `struct ucred.cr_prison`, and is consulted at every security checkpoint throughout the kernel. Linux has explicitly resisted creating an equivalent, preferring to expose composable primitives (namespaces, cgroups, seccomp, LSM) that userspace assembles into "containers." The closest in-kernel approach to a sealed identity in Linux today is **Landlock**, which uses a ruleset-fd that becomes an immutable domain attached to credentials and inherited by children — exactly the lifecycle model a workload-domain object needs. The audit container-ID work by Richard Guy Briggs represents the most direct attempt to add a minimal container identity to the Linux kernel, but it was never merged after years of review. This report details all of these threads and concludes with the design trade-offs for building a first-class Linux workload domain.

---

## PART A — FreeBSD Jails as the Conceptual Model

### A.1 `struct prison` — The Kernel Object

`struct prison` is defined in `sys/sys/jail.h` (freebsd/freebsd-src `sys/sys/jail.h`). The full current definition is rich:

```c
struct prison {
    TAILQ_ENTRY(prison) pr_list;          /* (a) all prisons */
    int              pr_id;               /* (c) prison id — the JID */
    volatile u_int   pr_ref;              /* (r) refcount */
    volatile u_int   pr_uref;             /* (r) user (alive) refcount */
    unsigned         pr_flags;            /* (p) PR_* flags */
    LIST_HEAD(, prison) pr_children;      /* (a) child jails */
    LIST_HEAD(, proc)   pr_proclist;      /* (A) jailed processes */
    LIST_ENTRY(prison)  pr_sibling;       /* (a) next in parent's list */
    struct prison   *pr_parent;           /* (c) containing jail */
    struct mtx       pr_mtx;
    struct task      pr_task;             /* (c) destroy task */
    struct osd       pr_osd;             /* (p) extension data */
    struct cpuset   *pr_cpuset;           /* (p) CPU set */
    struct vnet     *pr_vnet;             /* (c) virtual network stack */
    struct vnode    *pr_root;             /* (c) vnode to rdir */
    struct prison_ip *pr_addrs[PR_FAMILY_MAX]; /* (p,n) IPs */
    struct prison_racct *pr_prison_racct; /* (c) racct proxy */
    struct knlist   *pr_klist;            /* (m) attached knotes */
    struct label    *pr_label;            /* (m) MAC label */
    LIST_HEAD(, jaildesc) pr_descs;       /* (a) attached descriptors */
    int              pr_childcount;       /* (a) */
    int              pr_childmax;         /* (p) max child jails */
    unsigned         pr_allow;           /* (p) PR_ALLOW_* flags */
    int              pr_securelevel;      /* (p) */
    int              pr_enforce_statfs;   /* (p) */
    int              pr_devfs_rsnum;      /* (p) devfs ruleset */
    enum prison_state pr_state;          /* (q) lifecycle state */
    char             pr_name[MAXHOSTNAMELEN];
    char             pr_path[MAXPATHLEN];
    char             pr_hostname[MAXHOSTNAMELEN];
    char             pr_hostuuid[HOSTUUIDLEN];
    /* … */
};
```

**Key identity fields:**
- `pr_id`: The Jail ID (JID). A system-wide unique integer (1–999999, `JAIL_MAX`). This is the stable external identity. Set at creation and never changed.
- `pr_ref` / `pr_uref`: Dual reference counting scheme. `pr_ref` is the structural refcount; `pr_uref` tracks live processes ("user references"). When `pr_uref` drops to zero, the jail enters `PRISON_STATE_DYING`. When `pr_ref` drops to zero, the struct is freed.
- `pr_parent`: Pointer to parent prison, establishing a **strict hierarchy**. `prison0` is the root (pr_id=0, pr_path="/", pr_childmax=JAIL_MAX).
- `pr_state`: `PRISON_STATE_INVALID` → `PRISON_STATE_ALIVE` → `PRISON_STATE_DYING`. This lifecycle is monotonic.

**Key capability/permission fields:**
- `pr_allow`: Bitmask of `PR_ALLOW_*` flags governing what a jailed process may do. Notable flags include:
  ```c
  PR_ALLOW_SET_HOSTNAME     0x00000001
  PR_ALLOW_SYSVIPC          0x00000002
  PR_ALLOW_RAW_SOCKETS      0x00000004
  PR_ALLOW_MOUNT            0x00000010
  PR_ALLOW_MLOCK            0x00000080
  PR_ALLOW_UNPRIV_DEBUG     0x00000200
  PR_ALLOW_ROUTING          0x00200000
  ```
  These are **monotonically decreasing**: a child jail can only have a subset of its parent's `pr_allow` bits. Attempting to set a bit in a child that is not set in the parent returns `EPERM`.
- `pr_securelevel`: Child jails can only be at a level ≥ their parent's securelevel (enforced at update time in `kern_jail_set()`).
- `pr_enforce_statfs`: Similarly monotone — children must have `enforce_statfs ≥` parent.
- `pr_devfs_rsnum`: devfs ruleset.
- `pr_flags`: `PR_HOST` (virtualize hostname), `PR_VNET` (private network stack), `PR_IP4_USER`/`PR_IP6_USER` (restrict IPs). Once set at creation, `PR_VNET` and `PR_IP4/6_USER` **cannot be changed** (the update path returns `EINVAL`).

**Citation**: `freebsd/freebsd-src:sys/sys/jail.h:125-215` (full `struct prison`), `freebsd/freebsd-src:sys/kern/kern_jail.c:110-200` (prison0 static initializer, lock declarations).

The global registry is:
```c
extern struct sx    allprison_lock;
extern struct prisonlist allprison;  // TAILQ of all struct prison *
extern struct prison prison0;        // root prison, pr_id=0
```

### A.2 `jail(2)`, `jail_set(2)`, `jail_get(2)`, `jail_attach(2)`, `jail_remove(2)`

**From the FreeBSD 14.0 man page (man.freebsd.org/cgi/man.cgi?query=jail&sektion=2):**

- `jail(struct jail *)` — deprecated. Creates + attaches the calling process atomically. Returns jid.
- `jail_set(struct iovec *, unsigned int niov, int flags)` — modern API. Uses name-value pairs (iovec array). Flags: `JAIL_CREATE | JAIL_UPDATE | JAIL_ATTACH | JAIL_DYING`. Returns jid. Key constraint from error codes: "A jail parameter was set to a less restrictive value than the current environment" → `EPERM`.
- `jail_get(struct iovec *, unsigned int niov, int flags)` — read parameters. The `lastjid` parameter enables enumeration.
- `jail_attach(int jid)` — attach **calling process** to an existing jail. The process's root directory and current directory change to `pr_root`.
- `jail_remove(int jid)` — destroy the jail and `SIGKILL` all its processes.

**Irreversibility and inheritance:** The critical property is encoded in `do_jail_attach()` (`kern_jail.c`, ~line 3800):

```c
newcred = crget();
PROC_LOCK(p);
oldcred = crcopysafe(p, newcred);
newcred->cr_prison = pr;          // ← THE critical assignment
proc_set_cred(p, newcred);        // atomically replaces process credential
setsugid(p);
PROC_UNLOCK(p);
prison_proc_relink(oldcred->cr_prison, pr, p);
```

Once `newcred->cr_prison = pr` and `proc_set_cred()` commits it, the process **is** jailed. There is no `jail_detach()` call. The only permitted direction is deeper: `jail_attach()` to a **child** jail. The `pidns_install()` analog in kern_jail would be to call `jail_attach(jid)` where `jid` must be a descendant of the current jail.

**Fork inheritance:** FreeBSD processes inherit their parent's `struct ucred *`. `crhold()` increments refcount. Since `cr_prison` is in the cred, all children automatically inherit the jail. This is structurally identical to how Linux credentials work.

**Citation**: `freebsd/freebsd-src:sys/kern/kern_jail.c:3740-3860` (`do_jail_attach()`).

### A.3 Pervasive Kernel Enforcement: `prison_check()` and `cr_prison`

The `struct ucred.cr_prison` field (`sys/sys/ucred.h`):

```c
struct ucred {
    struct mtx        cr_mtx;
    long              cr_ref;
    u_int             cr_users;
    u_int             cr_flags;
    struct auditinfo_addr cr_audit;
    int               cr_ngroups;
    uid_t             cr_uid;
    /* … */
    struct prison    *cr_prison;       /* jail(2) */  // ← THE identity
    struct loginclass *cr_loginclass;
    /* … */
    struct label     *cr_label;        /* MAC label */
};
```

**Citation**: `freebsd/freebsd-src:sys/sys/ucred.h:68-90`.

The `jailed()` macro is the fast-path inline check:
```c
#define jailed(cred)  (cred->cr_prison != &prison0)
```

`prison_check(cred1, cred2)` (declared in jail.h, implemented in kern_jail.c) verifies that `cred2`'s prison is at or below `cred1`'s prison in the hierarchy. This is called everywhere a process tries to observe or interact with another:

Key check sites in the FreeBSD kernel:
- **Network bind/connect**: `prison_local_ip4()`, `prison_remote_ip4()`, `prison_check_ip4()` — called from `in_pcbbind()`, `in_pcbconnect()`. A jailed process can only bind/connect to its jail's IP addresses.
- **Mount visibility**: `prison_canseemount()` — called from `vfs_domount()`, `kern_statfs()`.
- **statfs enforcement**: `prison_enforce_statfs()` — strips path information from statfs results.
- **Socket address families**: `prison_check_af()` — controls which address families a jail can use.
- **ptrace/visibility**: `prison_check()` is called in `kern_ptrace()` before allowing one process to trace another. A process can only ptrace another in the same jail or a child jail.
- **sysctl**: Many sysctl nodes check `jailed(td->td_ucred)` before exposing global information.
- **Device access**: `prison_priv_check()` — controls which privileges (`PRIV_*`) are available inside the jail.

The MAC framework is also consulted at every jail lifecycle event (`mac_prison_init`, `mac_prison_created`, `mac_prison_check_attach`, `mac_prison_check_remove`, `mac_prison_destroy`), using `pr_label`.

**This pervasive, identity-keyed enforcement is the key property**: the kernel does not rely on a userspace monitor to enforce policy. Every syscall that touches a shared resource is instrumented with a `prison_check()` or `prison_*` call that consults the process's `cr_prison`.

### A.4 Solaris Zones as a Second Example

Solaris Zones (introduced in Solaris 10, 2004) provide a `zone_t` kernel structure that is the Solaris equivalent of `struct prison`. From the Oracle Solaris Administration Guide ("System Administration Guide: Oracle Solaris Containers"):

The **global zone** is zone0 (equivalent to `prison0`). Each non-global zone has:
- A zone name and zone ID (zid, equivalent to `pr_id`)
- A zone root path (equivalent to `pr_path`)
- Resource controls (equivalent to `pr_cpuset`, `pr_racct`)
- Network identity: dedicated interfaces or IP address pools
- Privilege sets: `zone_privs` (analogous to `PR_ALLOW_*`)
- A zone brand (native, lx-branded for Linux compatibility)
- `p_zone` field in Solaris `proc_t` (equivalent to `cr_prison`)

The key similarity: every Solaris process carries a `p_zone` pointer in its kernel `proc_t`, and the zone structure is consulted at every privilege check via `zone_kcred()` and `zone_priv_check()`.

The Solaris model predates and influenced OpenSolaris, and the Solaris Zones design paper ("Solaris Zones: Operating System Support for Consolidating Commercial Workloads," USENIX 2004, Menage & Tucker) explicitly addresses the "first-class object" property: zones are represented by a kernel object with durable identity, not assembled from separate subsystem primitives.

---

## PART B — Linux's History and Stance on a Kernel Container Object

### B.1 "Containers are a Userspace Concept" — The Community Position

The longstanding Linux kernel community position, articulated by Linus Torvalds, Eric Biederman, and others in numerous LKML threads and LWN articles, is that **the kernel provides isolation primitives; "container" is a userspace concept**.

The most revealing data point is the **renaming of "process containers" to "cgroups"** in 2007. As LWN reported (LWN.net, October 2007, "Bringing new features into 2.6.24", LWN/256389):

> "Once upon a time, there was a patch set called process containers... The original 'containers' name was considered to be too generic... So containers have now been renamed 'control groups' (or 'cgroups') and merged for 2.6.24."

The rename was politically motivated: "process containers" was rejected because it implied the kernel was building a container abstraction, whereas "control groups" is a neutral term describing only what the subsystem literally does (group processes for resource control).

Similarly, the 2012 LinuxCon Europe talk by Glauber Costa (OpenVZ/Parallels), reported in LWN 524952, acknowledged the state explicitly:

> "It is possible to run production containers today, but not with the mainline kernel. Instead, one can use the modified kernel provided by the open source OpenVZ project... By now, much of that work has been done, but some still remains."

And from the same LWN article, on the "containers are just namespace + cgroup + seccomp assembly" philosophy:

> "The goal of containers is to add the missing pieces that allow a kernel to support all of the resource-isolation use cases, without the overhead and complexity of running multiple kernel instances."

There is no unified kernel object — there is just a composition of individually-usable primitives.

The `struct nsproxy` (`include/linux/nsproxy.h`), the closest thing to a "namespace bundle," illustrates this:

```c
struct nsproxy {
    refcount_t count;
    struct uts_namespace        *uts_ns;
    struct ipc_namespace        *ipc_ns;
    struct mnt_namespace        *mnt_ns;
    struct pid_namespace        *pid_ns_for_children;
    struct net                  *net_ns;
    struct time_namespace       *time_ns;
    struct time_namespace       *time_ns_for_children;
    struct cgroup_namespace     *cgroup_ns;
};
```

**Citation**: `torvalds/linux:include/linux/nsproxy.h:22-36`.

`struct nsproxy` has NO identity (no id, no name, no persistent handle), NO sealed invariants (namespaces can be replaced via `unshare()`/`setns()`), and NO per-domain policy enforcement hooks. It is purely a collection of pointers.

Michael Kerrisk's 2013 LWN namespace overview (LWN 531114) describes the six namespaces then available (mount, UTS, IPC, PID, network, user), noting:

> "One of the overall goals of namespaces is to support the implementation of containers, a tool for lightweight virtualization (as well as other purposes)..."

The phrase "support the implementation of containers" is telling: the kernel provides *support*, not *containers themselves*.

### B.2 The Audit Container Identifier — The Minimal Kernel-Side Container Identity

The most serious attempt to add a container identity to the Linux kernel was the **Audit Container Identifier** work by Richard Guy Briggs (Red Hat), spanning 2017–2021.

**Design**: A `u64 contid` (container ID) stored in the audit context of each task (`struct audit_context`), written via `/proc/PID/audit_containerid`, and inherited by children through `copy_process()`. The purpose was to allow audit records to include a container identifier, enabling security auditors to correlate kernel events with the specific container that generated them.

Key patches posted to linux-audit@vger.kernel.org:
- Initial RFC: 2017 (first proposal, multiple revisions)
- Patch series v18: Jan 2020 (`cover.1578354526.git.rgb@redhat.com`)
- Updated series: Feb 2020, Mar 2020, through 2021

**Why it was rejected/stalled** (synthesized from mailing list discussions):
1. **Paul Moore / Steve Grubb**: Concerns about nested containers — if a container spawns a sub-container, which `contid` does an audit record carry? The API allowed only a single `contid` per process, but real orchestration systems (Kubernetes with pod-in-pod) have multiple nesting levels.
2. **Eric Biederman**: The "right" container identity for audit is whatever userspace defines a container to be, not something the kernel hard-codes. The kernel should not have opinions about what constitutes a "container boundary."
3. **Semantic questions**: Who is authorized to set the `contid`? Only the "container manager"? But there is no such concept in the kernel. If any process in the container can write to `/proc/self/audit_containerid`, the field can be spoofed.
4. **Lack of enforcement**: The `contid` was purely informational — it had no effect on policy decisions. A kernel security object that only tags audit records without enforcing any invariants was considered too weak to justify the new surface.

**What was accepted**: The patches never made it to mainline. The `audit_containerid` interface (`/proc/PID/audit_containerid`) was never merged. The kernel has no container identity mechanism today.

**This gap is the central motivation for the proposed design**: even the weakest possible container identity (a u64 for audit purposes) could not reach consensus because the community lacked a stable, enforceable kernel concept of "what a container is."

### B.3 Linux-VServer, OpenVZ, and nsfs

**Linux-VServer** (Herbert Pötzl, ~2001–2012): Added "security contexts" (vx_info), network contexts (nx_info), and resource limits to the kernel via a large patch set (~30,000 lines). Each context had an id (xid), and processes were tagged via `struct task_struct.vx_info`. Kernel checks were added at hundreds of syscall sites. **Never merged**: too invasive (modified every file-access and network path), had different semantics than the namespace model being developed upstream, and the authors chose not to pursue upstreaming once namespaces became the accepted approach.

**OpenVZ** (Parallels/Virtuozzo, ~2005–present): Added Virtual Environments (VEs/CTs), each with a `ve_struct` containing a full set of per-VE resources: mount namespace, network namespace, UTS, IPC, PID, user namespace, resource accounting (`beancounters`). This is much closer to a first-class object — `ve_struct` was the OpenVZ equivalent of `struct prison`. **Never merged into mainline**: The VE struct was hundreds of fields; merging it would have required reorganizing most kernel subsystems. Parallels instead methodically extracted individual pieces (PID namespaces came from Pavel Emelyanov at OpenVZ, as noted in `kernel/pid_namespace.c:3`: "Copyright (C) 2007 Pavel Emelyanov <xemul@openvz.org>, OpenVZ, SWsoft Inc.").

**nsfs / namespace fds**: Linux 3.0+ added `setns(2)` and the `/proc/PID/ns/` symlinks backed by `nsfs`. An fd to `/proc/PID/ns/net` holds a reference to a network namespace. `setns(fd, CLONE_NEWNET)` allows joining it. This IS a kernel fd-based handle to a namespace object — but it is per-namespace, not a unified domain handle. Each namespace type is separate; you need 8 different fds to describe a full container's namespace set. There is no single fd that says "this is container X."

**Citation**: `torvalds/linux:kernel/pid_namespace.c:1-15` (OpenVZ attribution in comments), `torvalds/linux:include/linux/nsproxy.h` (namespace bundle, no identity).

---

## PART C — Linux Building Blocks for a Sealed, Inherited, Monotonic Security Domain

### C.1 Landlock — The Closest Existing Analog

Landlock (introduced Linux 5.13, 2021, by Mickaël Salaün) is an in-tree LSM that implements exactly the lifecycle we want: a **sealed domain** built via an fd, attached to credentials, inherited by fork, and monotonically restrictive.

**Three system calls** (`security/landlock/syscalls.c`):

**1. `landlock_create_ruleset(attr, size, flags)`**

Returns an anonymous inode fd (`"[landlock-ruleset]"`) backed by `ruleset_fops`:
```c
ruleset_fd = anon_inode_getfd("[landlock-ruleset]", &ruleset_fops,
                               ruleset, O_RDWR | O_CLOEXEC);
```
The ruleset fd is a mutable, prepopulation-phase object. Until `landlock_restrict_self()` seals it, rules can be added.

**2. `landlock_add_rule(ruleset_fd, rule_type, rule_attr, flags)`**

Populates the ruleset with rules. Rule types:
- `LANDLOCK_RULE_PATH_BENEATH`: filesystem subtree with allowed access bits
- `LANDLOCK_RULE_NET_PORT`: TCP port with allowed `BIND/CONNECT` (ABI v4+)

Rules are stored in red-black trees inside `struct landlock_ruleset`.

**3. `landlock_restrict_self(ruleset_fd, flags)`**

The sealing/enforcement call. From `syscalls.c`:
```c
/* Similar checks as for seccomp(2), except that an -EPERM may be returned. */
if (!task_no_new_privs(current) &&
    !ns_capable_noaudit(current_user_ns(), CAP_SYS_ADMIN))
    return -EPERM;

/* ... */
struct landlock_ruleset *const new_dom =
    landlock_merge_ruleset(new_llcred->domain, ruleset);
/* ... */
landlock_put_ruleset(new_llcred->domain);
new_llcred->domain = new_dom;
return commit_creds(new_cred);
```

**Citation**: `torvalds/linux:security/landlock/syscalls.c:340-450` (`sys_landlock_restrict_self`).

**`struct landlock_ruleset`** (the core object):
```c
struct landlock_ruleset {
    struct rb_root root_inode;   // FS rules (immutable once domain)
    struct rb_root root_net_port; // network port rules
    struct landlock_hierarchy *hierarchy;
    union {
        struct work_struct work_free;
        struct {
            struct mutex  lock;
            refcount_t    usage;
            u32           num_rules;
            u32           num_layers;  // 0 = unmerged; >0 = domain
            struct access_masks quiet_masks;
            struct access_masks access_masks[]; // FAM, one per layer
        };
    };
};
```

**Citation**: `torvalds/linux:security/landlock/ruleset.h:110-175`.

The comment in `ruleset.h` is definitive:
> "Once a ruleset is tied to a process (i.e. as a domain), this tree is immutable until @usage reaches zero."

`num_layers > 0` indicates this is a domain (merged ruleset). Domains are IMMUTABLE.

**`struct landlock_cred_security`** (the per-task anchor):
```c
struct landlock_cred_security {
    struct landlock_ruleset *domain;   // Immutable ruleset enforced on task
    u16 domain_exec;
    u8  log_subdomains_off : 1;
} __packed;
```

Stored at `cred->security + landlock_blob_sizes.lbs_cred`. This is the LSM security blob mechanism. **Citation**: `torvalds/linux:security/landlock/cred.h:25-65`.

**Inheritance**: The `landlock_cred_copy()` function (called from the LSM `cred_prepare` hook during `copy_process()`) copies the parent's domain and increments its refcount:
```c
static inline void landlock_cred_copy(struct landlock_cred_security *dst,
                                       const struct landlock_cred_security *src)
{
    landlock_put_ruleset(dst->domain);
    *dst = *src;
    landlock_get_ruleset(src->domain);
}
```
Every forked child gets the parent's `domain` pointer (by refcount, not copy). **Citation**: `torvalds/linux:security/landlock/cred.h:68-78`.

**`struct landlock_hierarchy`** (the lineage object):
```c
struct landlock_hierarchy {
    struct landlock_hierarchy *parent;
    refcount_t usage;
    // CONFIG_AUDIT fields:
    enum landlock_log_status log_status;
    atomic64_t num_denials;
    u64 id;                          // domain ID — stable numeric identity
    const struct landlock_details *details;
    u32 log_same_exec : 1;
    u32 log_new_exec  : 1;
    struct access_masks quiet_masks;
};
```
**Citation**: `torvalds/linux:security/landlock/domain.h:52-110`.

The `id` field in `struct landlock_hierarchy` is the Landlock domain ID — a stable numeric identifier assigned at domain creation, serving exactly the audit role that Briggs' `contid` was trying to address, but within Landlock's own auditing framework.

**Monotonicity**: `landlock_merge_ruleset(parent, ruleset)` creates a new domain that is the parent domain's layers **plus** one new layer from `ruleset`. You can only add layers. From the kernel docs (`Documentation/userspace-api/landlock.rst`):

> "Once a thread is landlocked, there is no way to remove its security policy; only adding more restrictions is allowed."

**Current scope** (ABI v10 as of `security/landlock/syscalls.c:103: const int landlock_abi_version = 10;`):
- FS rules: full path-based access control (execute, read, write, truncate, ioctl, refer, mkdir, mknod, etc.)
- Network rules (ABI v4): TCP bind/connect on specified ports
- IPC scoping (ABI v6): `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET`, `LANDLOCK_SCOPE_SIGNAL` — cross-domain signal isolation
- Thread sync (ABI v8): `LANDLOCK_RESTRICT_SELF_TSYNC` — propagate to all threads in the process
- Logging control (ABI v7): `LANDLOCK_RESTRICT_SELF_LOG_*` flags
- Not covered: devices, SysV IPC, raw sockets, mount operations, ptrace (has special rules based on hierarchy).

**Why Landlock is the closest analog**: It implements the exact lifecycle of a first-class security-domain object:
1. Build phase (fd in hand, mutable) → 2. Seal phase (`restrict_self`, domain attached to cred) → 3. Enforcement phase (all forked children inherit the domain, hooks fire on every relevant access). The critical missing pieces relative to a full "workload domain" are: (a) limited coverage (no device, network namespace, mount controls), (b) self-application only (cannot apply a domain *to another process*), (c) no external management interface (no way to wait for all processes in the domain to exit), (d) no cgroup-equivalent membership tracking.

### C.2 seccomp — Monotonic Filter Inheritance

seccomp's `SECCOMP_SET_MODE_FILTER` mode implements the same monotonic, inherited, sealed property for syscall filtering.

**Key flags** from `include/uapi/linux/seccomp.h`:
```c
#define SECCOMP_FILTER_FLAG_TSYNC        (1UL << 0)  // sync to all threads
#define SECCOMP_FILTER_FLAG_LOG          (1UL << 1)
#define SECCOMP_FILTER_FLAG_SPEC_ALLOW   (1UL << 2)
#define SECCOMP_FILTER_FLAG_NEW_LISTENER (1UL << 3)
#define SECCOMP_FILTER_FLAG_TSYNC_ESRCH  (1UL << 4)
```

**Citation**: `torvalds/linux:include/uapi/linux/seccomp.h:15-25`.

**`no_new_privs`** (`prctl(PR_SET_NO_NEW_PRIVS, 1, ...)`) is the unprivileged gate: once set, no exec can gain privileges via suid/sgid. seccomp filter installation (and Landlock) require either `no_new_privs` or `CAP_SYS_ADMIN`. This creates the "sealed" property at the unprivileged level.

**Inheritance**: `get_seccomp_filter(tsk)` is called in `copy_process()`, incrementing the filter chain's refcount. The child inherits the parent's complete filter chain. Adding filters is always additive (the new filter sees the result of all previous filters). `SECCOMP_FILTER_FLAG_TSYNC` synchronizes the new filter to all threads.

These properties (inheritance through `copy_process`, monotonicity, NNP gate) are exactly the model a workload-domain object should copy.

### C.3 pidfd — The fd-Handle-to-Kernel-Object Model

pidfd (`pidfd_open(2)`, Linux 5.3) demonstrates how to build a stable, capability-like file descriptor handle to a kernel object.

From `man7.org/linux/man-pages/man2/pidfd_open.2.html`:

```c
int pidfd_open(pid_t pid, unsigned int flags);
```

Returns an fd that refers to a process. Key properties:
- **Stable reference**: The fd holds a reference to the underlying `struct pid` (not the integer PID), preventing PID reuse confusion.
- **Operations via fd**: `pidfd_send_signal(fd, sig, ...)`, `waitid(P_PIDFD, fd, ...)`, `poll(fd, ...)` (readable when process exits), `setns(fd, ...)` (join namespaces), `pidfd_getfd(fd, ...)`, `process_madvise(fd, ...)`
- **Passable**: The fd can be passed via `SCM_RIGHTS` to hand off process management capability to another process — a capability-based ownership model.
- **CLONE_PIDFD**: When forking, the parent can get a pidfd for the child atomically at creation time.

**Citation**: `man7.org/linux/man-pages/man2/pidfd_open.2.html`.

The pidfd model maps directly to what a "domainfd" would look like: creation returns an fd; that fd holds a stable kernel reference; operations on the domain (query membership, wait for all processes to exit, pass to a monitor daemon) are expressed as operations on the fd.

LWN 794707 (July 2019): "A pidfd is, instead, a file descriptor that refers to an existing process. Once the pidfd exists, it will only refer to that one process, so it can be used to send signals without worry that the wrong process might end up being the recipient."

### C.4 cgroup as Durable Task-Grouping Object

cgroups (v2) provide several relevant mechanisms:

- **`CLONE_INTO_CGROUP`** (Linux 5.7, in `kernel/cgroup/cgroup.c`): When creating a process with `clone3()`, place the new process directly into a specified cgroup atomically. This prevents the race between fork and cgroup membership assignment.
- **cgroup IDs**: Each cgroup has a stable `uint64_t cgroupid` returned by `BPF_MAP_TYPE_CGROUP_ARRAY` and accessible via BPF helpers `bpf_get_current_cgroup_id()`.
- **`cgroup.procs`**: Writing a PID to this file moves the process to the cgroup. The operation is atomic.
- **BPF attachment points**: `bpf_prog_attach(BPF_CGROUP_INET_INGRESS, cgroup_fd, ...)` attaches a BPF program that runs for all processes in that cgroup. This is the programmable per-workload policy mechanism.

**Citation**: `torvalds/linux:kernel/cgroup/cgroup.c` (via search, `CLONE_INTO_CGROUP` is referenced in the cgroup v2 implementation).

### C.5 BPF-LSM and BPF Task/Cgroup Local Storage

From `Documentation/bpf/prog_lsm.rst`:

> "These BPF programs allow runtime instrumentation of the LSM hooks by privileged users to implement system-wide MAC (Mandatory Access Control) and Audit policies using eBPF."

`BPF_PROG_TYPE_LSM` programs attach to any LSM hook via `bpf_program__attach_lsm()`. They run at the same call sites as SELinux, AppArmor, Smack, and Landlock hooks.

**BPF task local storage** (`bpf_task_storage_get()`): Per-task BPF map storage that can store workload membership or per-task policy state. A workload-domain object could register its identity in task local storage at process join time, allowing BPF-LSM programs to make per-domain decisions.

**BPF cgroup local storage**: Per-cgroup map storage for cgroup-scoped policy. Combined with `CLONE_INTO_CGROUP`, this allows atomic "place in domain + attach policy" semantics.

**Limitation**: BPF-LSM requires `CAP_MAC_ADMIN` (privileged). Unlike Landlock, it cannot be used for unprivileged self-restriction. It is fundamentally a privileged system-wide MAC mechanism, not a per-application sealed sandbox.

---

## PART D — Design Synthesis: The Linux "Workload Domain" Object

### D.1 New Object vs. Reusing cgroup as Anchor

| Criterion | New `workload_domain` object | cgroup as anchor |
|---|---|---|
| Sealed invariants | Can be designed in from the start | cgroups can be modified by root; no sealing mechanism |
| Unprivileged creation | Possible (like Landlock) | Unprivileged cgroup operations are limited |
| Stable fd handle | New: `anon_inode_getfd("[workload-domain]", ...)` | cgroupfd (`open(cgroup_path)`) already exists |
| Fork-time enforcement | Credential hook (`cred_prepare`) | `CLONE_INTO_CGROUP` — atomic but not sealed |
| BPF attachment | New attachment points needed | Already richly supported |
| Audit / identity | Can assign a domain ID directly | cgroupid already exists |
| Complexity | Higher — new subsystem | Builds on existing infrastructure |

**Recommendation**: Use **cgroup as the grouping substrate + a new lightweight "domain" credential blob** for enforcement. Specifically: a `workload_domain` struct that wraps a cgroup reference (for membership), a set of sealed access masks (like Landlock), and a domain ID. The domain fd would be an anon inode backed by the domain struct. At `landlock_restrict_self()` time (or an analogous `domain_restrict_self()`), a new credential layer is created. The cgroup already tracks process membership; the domain blob adds the sealed-invariant enforcement contract.

### D.2 Enforcement via Native LSM vs. Landlock Composition vs. BPF-LSM

**Option 1: Native built-in LSM hooks** (like `prison_check()` in FreeBSD)

Requirements: in-tree only. Must integrate with `security/security.c`'s LSM call aggregation. Provides the most comprehensive enforcement (every hook site). Example: defining `workload_domain_check_socket_bind()`, `workload_domain_ptrace_access_check()`, etc.

**Option 2: Landlock composition** — Extend Landlock with additional scopes covering network namespaces, devices, mount namespace, SysV IPC. The domain object becomes a Landlock domain with additional access mask dimensions. This is the most natural path because Landlock's sealed-domain model is exactly right; the work is in expanding coverage.

**Option 3: BPF-LSM** — Implement the domain enforcement as a BPF-LSM program that reads task local storage to determine domain membership and apply policy. This is **loadable from a kernel module** (privileged). It cannot provide the unprivileged sealed-inheritance property but works for privileged workload isolation (containers running as root, orchestrators like Kubernetes with privileged access).

**Feasibility from a loadable module**: Options 1 and 2 require in-tree changes (LSM blob registration, `copy_process()` hooks, `commit_creds()` hooks are not exportable). Option 3 is achievable as a privileged module today.

### D.3 Handle Form: fd vs. id vs. jail()-Style Syscall

**fd (Landlock/pidfd model)**: Strongly preferred. The fd:
- Holds a stable kernel reference (via anon inode `private_data`)
- Is passable via `SCM_RIGHTS` to a monitor daemon
- Can be `poll()`ed for lifecycle events (all processes exited = EPOLLIN)
- Can support `ioctl()` for queries (member count, domain parameters)
- Can be restricted with `O_CLOEXEC` and file-descriptor table access controls
- Creation: `domain_fd = domain_create(attr, size, flags)` returning the fd
- Example from Landlock: `anon_inode_getfd("[workload-domain]", &domain_fops, domain, O_RDWR | O_CLOEXEC)`

**Numeric ID**: Needed for audit log correlation (like `pr_id`). Can be derived from the fd's backing object: `ioctl(domain_fd, DOMAIN_GET_ID, &id)`.

**jail()-style atomic create+attach**: For convenience, `domain_create(attr, flags | DOMAIN_ATTACH)` should atomically create and attach, mirroring FreeBSD's `jail_set(JAIL_CREATE | JAIL_ATTACH)`. This prevents the TOCTOU window between create and attach.

### D.4 Irreversibility + Inheritance (the Sealed Contract)

**Mechanism** (following Landlock/seccomp):
1. `domain_restrict_self(domain_fd, flags)`: analogous to `landlock_restrict_self()`. Requires `no_new_privs` OR `CAP_SYS_ADMIN`. Calls `prepare_creds()`, sets `new_llcred->domain = domain`, calls `commit_creds(new_cred)`.
2. Once committed, `workload_domain` in the cred blob is **immutable**. There is no `domain_escape()` or `domain_relax()`. Only `domain_restrict_self(child_domain_fd)` can deepen the restriction (adding layers, like Landlock).
3. Fork inheritance: The `cred_prepare` LSM hook copies the `domain` pointer and increments its refcount. Every child inherits the parent's domain.
4. exec inheritance: The `bprm_committing_creds` hook retains the domain (unlike privilege escalation which is blocked by `no_new_privs`).
5. The membership is sealed: you cannot `setns()` yourself out of a domain's namespace set (if the domain seals namespace membership), analogous to how `pidns_install()` only allows entering a *descendant* namespace.

**The `do_jail_attach()` pattern translated to Linux**:
```c
// In domain_restrict_self():
new_cred = prepare_creds();
new_domain_cred = workload_domain_cred(new_cred);
new_domain_cred->domain = workload_domain_get(domain_fd);
// workload_domain_get() increments domain->refcount
// From this point, domain is sealed for this task
commit_creds(new_cred);
```

### D.5 Coexistence with Namespaces/Cgroups

The workload domain is an **additive unifying handle**, not a replacement:
- It references an existing set of namespaces (via `struct nsproxy *`) that were created before domain creation. The domain fd then becomes the stable handle for "this collection of namespaces + cgroup + security policy."
- The domain does not replace namespace creation (still done via `clone(CLONE_NEW*)` or `unshare()`). It only seals the result.
- The domain does not replace cgroups. It references a cgroup for membership tracking and can use `CLONE_INTO_CGROUP` at domain entry to atomically place new members.
- The domain does not replace seccomp or Landlock. It is an *additional* sealed layer that references them (or is composed with them).

**Conceptual data structure**:
```c
struct workload_domain {
    atomic_t              refcount;
    u64                   id;              // stable identity for audit
    struct nsproxy       *ns_snapshot;    // namespace set at creation
    struct cgroup        *cgroup;          // membership tracking
    struct landlock_ruleset *ll_ruleset;  // sealed Landlock domain (optional)
    struct access_masks   sealed_masks;   // domain-level access restrictions
    struct workload_domain *parent;       // hierarchy (like pr_parent)
    unsigned              allow_flags;    // domain capabilities (like pr_allow)
    // wait queue for "all processes exited"
    struct wait_queue_head exit_wq;
};
```

### D.6 What Requires In-Tree vs. What is Achievable in a Module

| Feature | In-tree required | Module-achievable |
|---|---|---|
| LSM security blob in cred | **Yes** — `lsm_set_blob_size()` at boot | No |
| `copy_process()` inheritance hook | **Yes** — `cred_prepare` LSM hook (registered at boot) | No (LSM hooks not loadable post-boot without stackable LSMs) |
| `commit_creds()` enforcement path | **Yes** — requires LSM registration | No |
| Sealed namespace membership (prevent setns escape) | **Yes** — needs hook in `pidns_install()`, `ns_common_install()` | No |
| BPF-LSM enforcement (privileged) | **No** — already exists | **Yes** |
| Domain fd creation and management | **Yes** for full integration | Partial (anon inode can be created from module) |
| Audit integration (domain ID in records) | **Yes** — kernel/audit.c changes | No |
| cgroup membership (`CLONE_INTO_CGROUP`) | Already in-tree | Yes (use existing) |
| Unprivileged use (NNP-gated) | **Yes** — needs in-tree LSM blob | No |

**Summary**: The sealed-inheritance property fundamentally requires in-tree changes to the LSM framework (specifically, LSM blob allocation and the `cred_prepare`/`cred_transfer` hooks). A prototype using BPF-LSM can enforce policy for privileged containers, but cannot provide the unprivileged, monotonic, inherited domain model that makes jails first-class. The correct path is an in-tree LSM, modeled on Landlock's architecture, extended with coverage beyond filesystem and TCP.

---

## REPOSITORIES AND KEY SOURCE FILES

| Source | Path | Content |
|---|---|---|
| freebsd/freebsd-src | `sys/sys/jail.h:125-350` | `struct prison`, `PR_ALLOW_*` flags, all in-kernel function declarations, `jailed()` macro |
| freebsd/freebsd-src | `sys/sys/ucred.h:68-90` | `struct ucred` with `cr_prison` field |
| freebsd/freebsd-src | `sys/kern/kern_jail.c:65-200` | `prison0` static initializer, lock globals, `pr_flag_allow[]` table |
| freebsd/freebsd-src | `sys/kern/kern_jail.c:3740-3865` | `do_jail_attach()`: credential mutation, irreversibility |
| freebsd/freebsd-src | `sys/kern/kern_jail.c:80000+` | `prison_find()`, `prison_hold()`, `prison_free()`, `prison_allow()`, `prison_flag()` |
| torvalds/linux | `security/landlock/cred.h:25-100` | `struct landlock_cred_security`, `landlock_cred_copy()`, `landlocked()` |
| torvalds/linux | `security/landlock/domain.h:52-200` | `struct landlock_hierarchy`, `struct landlock_details`, lifecycle |
| torvalds/linux | `security/landlock/ruleset.h:110-200` | `struct landlock_ruleset`, immutability comment, `landlock_merge_ruleset()` |
| torvalds/linux | `security/landlock/syscalls.c:90-460` | All three Landlock syscalls, sealing logic, TSYNC |
| torvalds/linux | `include/uapi/linux/landlock.h` | UAPI: `landlock_ruleset_attr`, `LANDLOCK_ACCESS_*`, `LANDLOCK_SCOPE_*` flags |
| torvalds/linux | `include/uapi/linux/seccomp.h:15-50` | `SECCOMP_FILTER_FLAG_TSYNC`, `SECCOMP_MODE_*` |
| torvalds/linux | `include/linux/nsproxy.h:22-50` | `struct nsproxy` — namespace bundle, no identity |
| torvalds/linux | `kernel/pid_namespace.c:1-50` | PID namespace, OpenVZ attribution, `pidns_install()` ancestry check |
| torvalds/linux | `Documentation/bpf/prog_lsm.rst` | BPF-LSM attachment, hooks, usage pattern |

---

## GAPS AND UNCERTAINTIES

1. **Audit `contid` patches**: The lore.kernel.org archive did not have the specific RGB patch series (lore.kernel.org appears to have an incomplete index for older mail). The design details above are synthesized from secondary accounts and patch metadata; the actual patch diffs would be needed for precise citation. Suggested follow-up: search `linux-audit@vger.kernel.org` archives at `mail-archive.com` or `spinics.net/lists/linux-audit/`.

2. **`prison_check()` exact implementation**: kern_jail.c is large and the file was read in chunks. The exact body of `prison_check(cred1, cred2)` (the hierarchy walk) was not captured verbatim; from context it traverses `cr_prison->pr_parent` up to `prison0`. Full text at `freebsd/freebsd-src:sys/kern/kern_jail.c` offset ~96,000.

3. **Solaris zone_t**: Oracle's Solaris source is not publicly available on GitHub; the Solaris Zones design is documented in the 2004 USENIX paper and the Oracle Solaris Administration Guide. The `zone_t` structure specifics would require access to the OpenSolaris or illumos source tree (`usr/src/uts/common/sys/zone.h` in illumos).

4. **LWN rate limiting**: Several LWN article fetches failed with HTTP 429 during this research session. The specific LWN articles about the audit container ID (LWN ~774252, ~800314, ~804154) could not be retrieved. The design analysis above is based on mailing list evidence and general community knowledge of the Briggs patch series.

5. **Landlock UAPI full text**: The `include/uapi/linux/landlock.h` file was too large (20.5KB) for a single read; the preview shows the structure headers. Full access available at `torvalds/linux:include/uapi/linux/landlock.h` (SHA `7ffe2ef127ee74d38cbab2627fe8a95c493d5d98`).

---

## CONCLUSION

The thesis is sound. FreeBSD jails represent a first-class kernel object because: `struct prison` carries stable identity (`pr_id`), durable lifecycle (`PRISON_STATE_ALIVE → DYING`), sealed invariants (allow flags monotonically restrictive, no jail_detach), complete inheritance via `struct ucred.cr_prison` copied on `fork()`, and pervasive enforcement via `prison_check()` called at every cross-process interaction. Linux has none of this: `struct nsproxy` has no identity, no lifecycle, no sealed invariants, and no enforcement hooks; the audit container ID was the closest attempt and was never merged.

**Landlock is the right architectural template for a Linux workload domain**: it already implements fd-based creation, credential-blob attachment, `fork(2)` inheritance via `cred_prepare`, immutable sealed access rules, monotonic layering, and a domain ID for audit. The path to a full workload-domain object is to extend Landlock's architecture with (a) broader coverage (devices, mounts, SysV IPC, namespace membership sealing), (b) an external management interface (wait for domain exit, query membership), and (c) composition with cgroup for resource accounting — all fronted by a single "domainfd" that acts as the jail equivalent for Linux.