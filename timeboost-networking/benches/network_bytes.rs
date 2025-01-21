use bytes::Bytes;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_clone_single_bytes(c: &mut Criterion) {
    let data = Bytes::from(vec![0u8; 2_000]); // 2KB
    c.bench_function("clone_single_bytes", |b| {
        b.iter(|| {
            let cloned = black_box(data.clone());
            black_box(cloned);
        })
    });
}

fn bench_clone_single_vec_u8(c: &mut Criterion) {
    let data = vec![0u8; 2_000]; // 2KB
    c.bench_function("clone_single_vec_u8", |b| {
        b.iter(|| {
            let cloned = black_box(data.clone());
            black_box(cloned);
        })
    });
}

fn bench_clone_vec_of_bytes(c: &mut Criterion) {
    let data: Vec<Bytes> = (0..64).map(|i| Bytes::from(vec![0; i * 1024])).collect();
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
    let data: Vec<Vec<u8>> = (0..64).map(|i| vec![0; i * 1024]).collect();
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
