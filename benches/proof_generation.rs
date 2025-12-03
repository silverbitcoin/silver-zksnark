use criterion::{black_box, criterion_group, criterion_main, Criterion};
use silver_zksnark::ProofGenerator;

fn bench_key_generation(c: &mut Criterion) {
    c.bench_function("key_generation", |b| {
        b.to_async(tokio::runtime::Runtime::new().unwrap())
            .iter(|| async { ProofGenerator::generate_keys().expect("Failed to generate keys") });
    });
}

fn bench_time_estimation(c: &mut Criterion) {
    let generator = ProofGenerator::new(false);

    c.bench_function("estimate_100_tx", |b| {
        b.iter(|| generator.estimate_generation_time(black_box(100)))
    });

    c.bench_function("estimate_50000_tx", |b| {
        b.iter(|| generator.estimate_generation_time(black_box(50000)))
    });
}

criterion_group!(benches, bench_key_generation, bench_time_estimation);
criterion_main!(benches);
