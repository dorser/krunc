//! `cpuhog` — a deterministic probe for the cgroup v2 cpu controller.
//!
//! It runs a CPU-bound loop for a fixed wall-clock window. When the enclosing
//! cgroup has a `cpu.max` quota, the kernel CFS bandwidth controller throttles
//! the cgroup (parking the task at period boundaries), which the host observes
//! as `cpu.stat`'s `nr_throttled` / `throttled_usec` climbing — proof the limit
//! is enforced. Plain safe Rust: arithmetic in a loop, no allocation.

#![forbid(unsafe_code)]

use std::io::Write;
use std::time::{Duration, Instant};

/// Wall-clock window to stay busy (the host samples `cpu.stat` during this).
const RUN: Duration = Duration::from_secs(3);

fn main() {
    let mut err = std::io::stderr();
    let start = Instant::now();
    let mut sink: u64 = 0;
    let mut mloops: u64 = 0;

    while start.elapsed() < RUN {
        for _ in 0..1_000_000 {
            // A cheap, non-optimizable-away mix (an LCG step).
            sink = sink
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
        }
        mloops += 1;
    }

    let _ = writeln!(
        err,
        "[cpuhog] ran {:.1}s wall doing {} Mloops (sink={}) -- the cgroup cpu.max throttled this if set",
        start.elapsed().as_secs_f32(),
        mloops,
        sink & 0xff
    );
    let _ = err.flush();
}
