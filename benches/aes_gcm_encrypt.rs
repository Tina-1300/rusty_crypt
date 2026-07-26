use std::hint::black_box;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use rusty_crypt::{AesGcmEncrypt, AesGcmGeneratedNonce};
use std::time::Duration;

fn criterion_config() -> Criterion {
    Criterion::default()
        .sample_size(200)
        .measurement_time(Duration::from_secs(10))
}

fn aes_gcm_encrypt(c: &mut Criterion) {
    let key = [0u8; 32];

    let nonce_generator = AesGcmGeneratedNonce;
    let encryptor = AesGcmEncrypt::new(&nonce_generator);

    let mut group = c.benchmark_group("AES-256-GCM Encrypt");

    let sizes = [
        ("64 B", 64),
        ("1 KiB", 1024),
        ("1 MiB", 1024 * 1024),
        ("10 MiB", 10 * 1024 * 1024),
    ];

    for (name, size) in sizes {
        let data = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(BenchmarkId::new("encrypt_bytes", name), &data, |b, data| {
            b.iter(|| {
                black_box(
                    encryptor
                        .encrypt_bytes(black_box(data), black_box(&key))
                        .unwrap(),
                );
            });
        });
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = aes_gcm_encrypt
}
criterion_main!(benches);
