//! Time-to-sync N ops: boot a producer and a consumer on loopback, commit N ops
//! on the producer, and measure the wall time for the consumer to pull to the
//! producer's head. Sweeps N (override on the command line, e.g.
//! `cargo run --example bench_sync --features harness -- 1 10 100 1000`) and
//! prints one JSON record per size. No assertions — the functional tests own
//! pass/fail; this only records numbers for tracking across commits.

use std::time::Instant;

use proxy_node_server::KvOp;
use proxy_node_server::harness::MeshNode;

#[tokio::main]
async fn main() {
    let sizes: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|s| s.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![1, 10, 100, 1000]
    } else {
        sizes
    };

    println!("{{\"bench\":\"time_to_sync\"}}");
    for n in sizes {
        let producer = MeshNode::spawn().await;
        let consumer = MeshNode::spawn().await;

        for i in 0..n {
            producer.commit(&KvOp::Put {
                key: format!("k{i}"),
                value: (i as u64).to_le_bytes().to_vec(),
            });
        }
        let target = producer.head();

        let start = Instant::now();
        loop {
            consumer.sync_from(&producer).await;
            if consumer.head() == target {
                break;
            }
        }
        let elapsed = start.elapsed();

        let t_ms = elapsed.as_secs_f64() * 1e3;
        let ops_per_s = if elapsed.as_secs_f64() > 0.0 {
            n as f64 / elapsed.as_secs_f64()
        } else {
            0.0
        };
        println!("{{\"n\":{n},\"t_ms\":{t_ms:.3},\"ops_per_s\":{ops_per_s:.1}}}");
    }
}
