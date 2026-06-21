//! `memhog` — a deterministic probe for the cgroup v2 memory controller.
//!
//! It allocates memory in chunks and **touches every page** (so the pages are
//! actually faulted in and charged to the enclosing cgroup), printing progress,
//! until the cgroup's `memory.max` is reached and the kernel OOM-kills it. The
//! host then observes `memory.events` (`oom`/`oom_kill` ≥ 1) and sees this
//! process gone — proof that the limit is enforced, not merely set.
//!
//! It is plain safe Rust: `Vec` allocation plus a write to one byte per page.

#![forbid(unsafe_code)]

use std::io::Write;

/// Allocation granularity (also the cadence of progress output).
const CHUNK: usize = 8 * 1024 * 1024; // 8 MiB
const PAGE: usize = 4096;
/// Hard ceiling so a missing/blank limit can't make this run forever.
const MAX_TOTAL: usize = 4 * 1024 * 1024 * 1024; // 4 GiB

fn main() {
    let mut err = std::io::stderr();
    let mut held: Vec<Vec<u8>> = Vec::new();
    let mut total = 0usize;

    while total < MAX_TOTAL {
        let mut chunk = vec![0u8; CHUNK];
        // Fault in every page; without this the kernel may not charge the
        // pages to the cgroup and the limit would never bite.
        let mut i = 0;
        while i < chunk.len() {
            chunk[i] = 0xa5;
            i += PAGE;
        }
        held.push(chunk);
        total += CHUNK;
        let _ = writeln!(err, "[memhog] resident {} MiB", total / (1024 * 1024));
        let _ = err.flush();
    }

    // Only reached if no limit applied (the cgroup OOM kill normally ends us
    // mid-loop). Keep the pages resident so a caller can still inspect us.
    let _ = writeln!(err, "[memhog] reached {} MiB ceiling without an OOM kill", MAX_TOTAL / (1024 * 1024));
    let _ = err.flush();
    std::process::exit(0);
}
