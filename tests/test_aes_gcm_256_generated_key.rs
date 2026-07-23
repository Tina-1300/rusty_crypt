#[cfg(test)]
mod tests {
    use rusty_crypt::aes_gcm_256_generated_key::AesGeneratedKey;

    #[test]
    fn test_checked_type_generated_key_aes_gcm_256() {
        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        assert_eq!(key.len(), 32, "Key should be 32 bytes long for AES GCM 256");
    }

    #[test]
    fn test_generated_key_is_not_zeroed() {
        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        assert!(
            key.iter().any(|&byte| byte != 0),
            "Generated key should not be all zeros"
        );
    }
}
