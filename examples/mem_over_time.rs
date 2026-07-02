//! Memory over time during a long-running sync: a producer commits a growing
//! op-log while a consumer periodically pulls it, and the harness samples this
//! process's resident set size (via `ps`, macOS/Linux) at each checkpoint.
//! Prints a JSON time series. Override the op count on the command line, e.g.
//! `cargo run --example mem_over_time --features harness -- 4000`.

use std::time::Instant;

use proxy_node_server::KvOp;
use proxy_node_server::harness::{MeshNode, rss_kib};

#[tokio::main]
async fn main() {
    let total: usize = std::env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(2_000);
    let sample_every = (total / 20).max(1);
    let pid = std::process::id();

    let producer = MeshNode::spawn().await;
    let consumer = MeshNode::spawn().await;

    println!("{{\"bench\":\"mem_over_time\",\"pid\":{pid},\"total\":{total}}}");
    let start = Instant::now();
    for i in 0..total {
        producer.commit(&KvOp::Put {
            key: format!("k{i}"),
            value: (i as u64).to_le_bytes().to_vec(),
        });
        if i % sample_every == 0 {
            consumer.sync_from(&producer).await;
            let rss = rss_kib(pid).unwrap_or(0);
            let t_ms = start.elapsed().as_secs_f64() * 1e3;
            let len = consumer.log_len();
            println!("{{\"i\":{i},\"t_ms\":{t_ms:.1},\"log_len\":{len},\"rss_kib\":{rss}}}");
        }
    }
}
