use std::hint::black_box;
use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};

use criterion_cycles_per_byte::CyclesPerByte;

use rusty_crypt::{AesGcm256Key, AesGcmEncrypt, AesGcmGeneratedNonce};

fn criterion_config() -> Criterion<CyclesPerByte> {
    Criterion::default()
        .with_measurement(CyclesPerByte)
        .sample_size(50)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(3))
}

fn aes_gcm_encrypt(c: &mut Criterion<CyclesPerByte>) {
    let key = AesGcm256Key::from_bytes([0u8; AesGcm256Key::SIZE]);

    let nonce_generator = AesGcmGeneratedNonce;

    let encryptor =
        AesGcmEncrypt::new(&nonce_generator, &key).expect("Encryptor creation should succeed");

    let mut group = c.benchmark_group("AES-256-GCM Encrypt");

    let sizes = [
        ("1 B", 1),
        ("16 B", 16),
        ("32 B", 32),
        ("64 B", 64),
        ("128 B", 128),
        ("256 B", 256),
        ("512 B", 512),
        ("1 KiB", 1024),
        ("4 KiB", 4 * 1024),
        ("16 KiB", 16 * 1024),
        ("64 KiB", 64 * 1024),
        ("256 KiB", 256 * 1024),
        ("1 MiB", 1024 * 1024),
        ("4 MiB", 4 * 1024 * 1024),
        ("16 MiB", 16 * 1024 * 1024),
        ("32 MiB", 32 * 1024 * 1024),
        ("64 MiB", 64 * 1024 * 1024),
        ("128 MiB", 128 * 1024 * 1024),
        ("256 MiB", 256 * 1024 * 1024),
    ];

    for (name, size) in sizes {
        let plaintext = vec![0u8; size];

        group.throughput(Throughput::Bytes(size as u64));

        group.bench_with_input(
            BenchmarkId::new("encrypt_bytes", name),
            &plaintext,
            |b, plaintext| {
                b.iter(|| {
                    let (ciphertext, nonce) = encryptor
                        .encrypt_bytes(black_box(plaintext))
                        .expect("Encryption should succeed");

                    black_box(ciphertext);
                    black_box(nonce);
                });
            },
        );
    }

    group.finish();
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = aes_gcm_encrypt
}

criterion_main!(benches);
