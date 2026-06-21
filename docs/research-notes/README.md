# research notes

These are the cited research reports that the krunc v2 design
(`docs/ARCHITECTURE.md`, `docs/SECURITY.md`) rests on. They were produced during
the design phase and contain the primary-source citations (kernel files, man
pages, CVE advisories, LWN, the OCI spec, FreeBSD/Landlock sources).

| file | topic |
|---|---|
| `01-oci-runtime-spec.md` | OCI Runtime Specification: lifecycle, state, `config.json` schema, hooks, ordering |
| `02-setup-security-and-cves.md` | The runc-init transition attack surface; CVE analysis; security-critical setup ordering; kernel/userspace split |
| `03-post-setup-escapes-and-enforcement.md` | Post-setup escape classes; continuous in-kernel enforcement (seccomp/caps/Landlock/BPF-LSM); the honest VM-isolation boundary |
| `04-kernel-apis-and-rfl.md` | In-kernel C APIs vs Rust-for-Linux abstractions at v6.18; what is exported / `__init` / needs a shim |
| `05-bsd-jails-and-prior-art.md` | FreeBSD jails (`struct prison`), Linux's "no container object" history, Landlock as the template, design synthesis |
| `06-conformance-and-testing.md` | OCI runtime-tools conformance, youki/crun test patterns, containerd e2e, how to prove confinement from outside |

They are verbose, machine-generated literature reviews kept for design rationale
and traceability. The distilled conclusions live in the design docs.
