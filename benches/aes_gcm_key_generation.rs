use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use rusty_crypt::AesGeneratedKey;

fn criterion_config() -> Criterion<CyclesPerByte> {
    Criterion::default()
        .with_measurement(CyclesPerByte)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(3))
}

fn aes_gcm_key_generation(c: &mut Criterion<CyclesPerByte>) {
    let key_generator = AesGeneratedKey;

    c.bench_function("AES-256-GCM key generation", |b| {
        b.iter(|| {
            let key = key_generator
                .generate_key()
                .expect("Key generation should succeed");

            black_box(key);
        });
    });
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = aes_gcm_key_generation
}

criterion_main!(benches);
