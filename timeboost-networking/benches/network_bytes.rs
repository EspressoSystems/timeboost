use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_clone_bytes(c: &mut Criterion) {
    let data = Bytes::from(vec![0u8; 2_000]); // 2KB
    c.bench_function("clone_bytes_crate", |b| {
        b.iter(|| {
            let cloned = black_box(data.clone());
            black_box(cloned);
        })
    });
}

fn bench_clone_vec(c: &mut Criterion) {
    let data = vec![0u8; 2_000]; // 2KB
    c.bench_function("clone_vec_bytes", |b| {
        b.iter(|| {
            let cloned = black_box(data.clone());
            black_box(cloned);
        })
    });
}

criterion_group!(benches, bench_clone_bytes, bench_clone_vec);
criterion_main!(benches);
