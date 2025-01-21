use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

const ONE_KB: usize = 1024;
const MAX_NUM_KB: usize = 64;

fn bench_clone_single_bytes(c: &mut Criterion) {
    // Clone 2KB
    let data = Bytes::from(vec![0u8; ONE_KB * 2]);
    c.bench_function("clone_single_bytes", |b| {
        b.iter(|| {
            let cloned = black_box(data.clone());
            black_box(cloned);
        })
    });
}

fn bench_clone_single_vec_u8(c: &mut Criterion) {
    // Clone 2KB
    let data = vec![0u8; ONE_KB * 2];
    c.bench_function("clone_single_vec_u8", |b| {
        b.iter(|| {
            let cloned = black_box(data.clone());
            black_box(cloned);
        })
    });
}

fn bench_clone_vec_of_bytes(c: &mut Criterion) {
    // Clone 1KB - 64KB
    let data: Vec<Bytes> = (1..MAX_NUM_KB)
        .map(|i| Bytes::from(vec![0u8; i * ONE_KB]))
        .collect();
    c.bench_function("clone_vec_of_bytes", |b| {
        b.iter(|| {
            for d in data.iter() {
                let cloned = black_box(d.clone());
                black_box(&cloned);
            }
        })
    });
}

fn bench_clone_vec_of_vec_u8(c: &mut Criterion) {
    // Clone 1KB - 64KB
    let data: Vec<Vec<u8>> = (1..MAX_NUM_KB).map(|i| vec![0u8; i * ONE_KB]).collect();
    c.bench_function("clone_vec_of_vec_u8", |b| {
        b.iter(|| {
            for d in data.iter() {
                let cloned = black_box(d.clone());
                black_box(&cloned);
            }
        })
    });
}

criterion_group!(
    benches,
    bench_clone_single_bytes,
    bench_clone_single_vec_u8,
    bench_clone_vec_of_bytes,
    bench_clone_vec_of_vec_u8
);
criterion_main!(benches);
