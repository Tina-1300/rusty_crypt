#[cfg(test)]
mod tests {
    use rusty_crypt::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;

    #[test]
    fn test_checked_type_generated_nonce_aes_gcm_256() {
        let nonce = AesGcmGeneratedNonce
            .generate_nonce()
            .expect("Nonce generation should succeed");

        assert_eq!(
            nonce.len(),
            12,
            "Nonce should be 12 bytes long for AES GCM 256"
        );
    }

    #[test]
    fn test_generated_nonce_should_be_random() {
        let nonce_generator = AesGcmGeneratedNonce;

        let nonce1 = nonce_generator
            .generate_nonce()
            .expect("Nonce generation should succeed");

        let nonce2 = nonce_generator
            .generate_nonce()
            .expect("Nonce generation should succeed");

        assert_ne!(nonce1, nonce2, "Generated nonces should not be identical");
    }
}
