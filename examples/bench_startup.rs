//! Daemon startup cost as a function of pre-seeded op-log size: build a log of S
//! ops, then time replaying it into a fresh store plus reading the head — the
//! work a daemon does before it can first serve `/head`. Sweeps S to expose how
//! replay cost grows with history (override on the command line, e.g.
//! `cargo run --example bench_startup --features harness -- 100 1000 10000`).

use std::time::Instant;

use proxy_node_server::harness::seeded_log;
use proxy_node_server::{KvStore, replay};

fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![100, 1_000, 10_000]
    } else {
        sizes
    };

    println!("{{\"bench\":\"startup_replay\"}}");
    for s in sizes {
        let (log, _registry) = seeded_log(s);

        let start = Instant::now();
        let mut store = KvStore::new();
        replay(&log, &mut store).unwrap();
        let head = log.head();
        let t_ms = start.elapsed().as_secs_f64() * 1e3;

        assert!(head.is_some() || s == 0);
        let per_op_us = if s > 0 { (t_ms * 1e3) / s as f64 } else { 0.0 };
        println!("{{\"seeded_ops\":{s},\"replay_ms\":{t_ms:.3},\"per_op_us\":{per_op_us:.3}}}");
    }
}
