//! Criterion micro-benchmarks for the pure-CPU, runtime-independent hot paths:
//! sealing/verifying an op, the postcard envelope round-trip, op-log paging and
//! append, and order-key comparison. Wall-clock multi-process metrics
//! (time-to-sync, startup, memory) live in the `examples/` timing scripts, which
//! criterion's sampling model is the wrong tool for.

use std::hint::black_box;

use criterion::{Criterion, criterion_group, criterion_main};
use proxy_node_server::kv::kv_store_id;
use proxy_node_server::{
    DeviceIdentity, ENVELOPE_VERSION, Hlc, KvOp, KvStore, OpBody, OpLog, OrderKey, SignedOp, Store,
};

fn payload() -> Vec<u8> {
    KvStore::new()
        .encode(&KvOp::Put {
            key: "some/key".into(),
            value: vec![1, 2, 3, 4, 5, 6, 7, 8],
        })
        .unwrap()
}

fn op_at(id: &DeviceIdentity, hlc: u64, payload: Vec<u8>) -> SignedOp {
    let body = OpBody {
        v: ENVELOPE_VERSION,
        hlc: Hlc(hlc),
        device: id.device_id(),
        store: kv_store_id(),
        payload,
    };
    SignedOp::seal(body, id).unwrap()
}

fn bench_seal(c: &mut Criterion) {
    let id = DeviceIdentity::generate();
    let payload = payload();
    c.bench_function("op/seal", |b| {
        b.iter(|| {
            let body = OpBody {
                v: ENVELOPE_VERSION,
                hlc: Hlc(42),
                device: id.device_id(),
                store: kv_store_id(),
                payload: payload.clone(),
            };
            black_box(SignedOp::seal(black_box(body), &id).unwrap())
        })
    });
}

fn bench_verify(c: &mut Criterion) {
    let id = DeviceIdentity::generate();
    let op = op_at(&id, 42, payload());
    let key = *id.verifying_key();
    c.bench_function("op/verify", |b| {
        b.iter(|| black_box(op.verify(black_box(&key))).unwrap())
    });
}

fn bench_envelope_round_trip(c: &mut Criterion) {
    let id = DeviceIdentity::generate();
    let op = op_at(&id, 42, payload());
    c.bench_function("op/to_bytes", |b| {
        b.iter(|| black_box(op.to_bytes()).unwrap())
    });
    let bytes = op.to_bytes().unwrap();
    c.bench_function("op/from_bytes", |b| {
        b.iter(|| black_box(SignedOp::from_bytes(black_box(&bytes))).unwrap())
    });
}

fn bench_log(c: &mut Criterion) {
    let id = DeviceIdentity::generate();
    let ops: Vec<SignedOp> = (0..1000).map(|i| op_at(&id, i, payload())).collect();

    c.bench_function("log/append_1k", |b| {
        b.iter(|| {
            let mut log = OpLog::new();
            for op in &ops {
                log.append(op.clone());
            }
            black_box(log.len())
        })
    });

    let mut log = OpLog::new();
    for op in &ops {
        log.append(op.clone());
    }
    let mid = ops[500].order_key();
    c.bench_function("log/since_from_mid_1k", |b| {
        b.iter(|| black_box(log.since(black_box(mid)).count()))
    });
}

fn bench_order_key(c: &mut Criterion) {
    let id = DeviceIdentity::generate();
    let a = op_at(&id, 10, payload()).order_key();
    let b = op_at(&id, 11, payload()).order_key();
    c.bench_function("order_key/compare", |bench| {
        bench.iter(|| black_box(black_box(&a) < black_box(&b)))
    });
    c.bench_function("order_key/to_wire", |bench| {
        bench.iter(|| black_box(OrderKey::to_wire(black_box(&a))))
    });
}

criterion_group!(
    benches,
    bench_seal,
    bench_verify,
    bench_envelope_round_trip,
    bench_log,
    bench_order_key
);
criterion_main!(benches);
