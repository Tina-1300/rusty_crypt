use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use criterion_cycles_per_byte::CyclesPerByte;

use rusty_crypt::AesGcmGeneratedNonce;

fn criterion_config() -> Criterion<CyclesPerByte> {
    Criterion::default()
        .with_measurement(CyclesPerByte)
        .sample_size(100)
        .measurement_time(Duration::from_secs(5))
        .warm_up_time(Duration::from_secs(3))
}

fn aes_gcm_nonce_generation(c: &mut Criterion<CyclesPerByte>) {
    let nonce_generator = AesGcmGeneratedNonce;

    c.bench_function("AES-GCM nonce generation", |b| {
        b.iter(|| {
            let nonce = nonce_generator
                .generate_nonce()
                .expect("Nonce generation should succeed");

            black_box(nonce);
        });
    });
}

criterion_group! {
    name = benches;
    config = criterion_config();
    targets = aes_gcm_nonce_generation
}

criterion_main!(benches);
