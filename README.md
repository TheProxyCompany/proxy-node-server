# proxy-node-server

[![CI](https://github.com/TheProxyCompany/proxy-node-server/actions/workflows/ci.yml/badge.svg)](https://github.com/TheProxyCompany/proxy-node-server/actions/workflows/ci.yml)

The open mesh/sync layer of the Proxy network.

Status: early, pre-1.0, and built in the open. The API surface will change.

## What it is

`proxy-node-server` is a Rust library crate plus a reference daemon (`pnsd`).
The library is a signed op-log replication engine: each device holds a P-256
identity, stamps its operations with a hybrid logical clock (HLC, backed by
[`uhlc`](https://crates.io/crates/uhlc)), signs and content-addresses them, and
replays every peer's operations in one global total order — `(HLC, device id,
op id)`, so distinct ops never collide. Stores are pluggable — anything that
implements the `Store` trait (the crate ships a toy in-memory key/value store as
the reference implementor) plugs its own encoding and conflict repair into the
shared log while the engine stays semantics-free.

Replication is an incremental HTTP pull, behind the `pull-http` feature: a node
serves `/identity`, `/ops`, `/head`, and `/devices`, and pulls each peer with a
persisted `(HLC, device id, op id)` cursor. Every pulled op is verified against
the device registry — a peer's log carries ops from several devices — before it
is folded, appended, and applied. Applying is either a whole-log `replay`
(`ApplyMode::Replay`, correct for arrival-order stores like the toy KV) or an
incremental apply of just the ops a batch newly crossed (`ApplyMode::Incremental`,
O(batch) per pull, for stores with an internal per-row version guard). The
reference daemon persists its log to an append-only `oplog.bin` and replays it
at startup.

The mesh is N-peer. `/devices` gossips every device a node vouches for, so a
puller learns the verifying key of a device it never contacted directly (a
third party whose ops a peer relays) — each key admitted only if it derives its
advertised id, and persisted before it is allowed to verify an op. Peers can be
supplied statically or found through the provider-agnostic `discovery` seams
(`PresenceProvider` + `PeerTransport`): an mDNS/Bonjour LAN provider
(`discovery-mdns`) and a Tailscale provider that shells the local `tailscale`
LocalAPI (`discovery-tailscale`), each behind its own feature so a default build
pulls in neither.

The library is the primary artifact and builds with no default features, so
consumers pull the smallest dependency graph. The `pnsd` daemon builds under the
`daemon` feature; networked replication (axum, tokio, reqwest) is gated behind
`pull-http`. Discovery providers and the in-process multi-daemon test/perf
`harness` are each feature-gated and never leak into the default graph.

## Benchmarks

```bash
# Pure-CPU micro-ops (seal/verify/postcard/log paging), Criterion:
cargo bench --all-features

# Wall-clock timing scripts (loopback multi-daemon), JSON to stdout:
cargo run --example bench_sync    --features harness -- 1 10 100 1000
cargo run --example bench_startup --features harness -- 100 1000 10000
cargo run --example mem_over_time --features harness -- 4000
```

## Build and test

```bash
# Library only (consumer mode)
cargo build --no-default-features

# Everything, including the pnsd daemon
cargo build --all-features
cargo test --all-features

# Reference daemon
cargo run --features daemon --bin pnsd -- --version
cargo run --features daemon --bin pnsd -- identity init
cargo run --features daemon --bin pnsd -- identity show --json

# Two-node replication (each node needs its own data dir + device key)
cargo run --features pull-http --bin pnsd -- \
    serve --data-dir ./node-a --listen 127.0.0.1:51713 \
    --peer http://127.0.0.1:51714
```

MSRV is Rust 1.85 (edition 2024).

## License

Licensed under the [Apache License, Version 2.0](LICENSE). See [NOTICE](NOTICE).
