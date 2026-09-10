#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose};

    use rusty_crypt::{AesGcm256Key, AesGeneratedKey, CryptoError};

    #[test]
    fn test_aes_gcm_256_generated_key_has_expected_size() {
        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        assert_eq!(AesGcm256Key::SIZE, 32, "AES-256 key size must be 32 bytes");

        assert_eq!(
            key.size(),
            AesGcm256Key::SIZE,
            "Generated key must have the AES-256 key size"
        );
    }

    #[test]
    fn test_aes_gcm_256_generated_keys_are_different() {
        let generator = AesGeneratedKey;

        let key1 = generator
            .generate_key()
            .expect("First key generation should succeed");

        let key2 = generator
            .generate_key()
            .expect("Second key generation should succeed");

        assert!(
            !key1.is_equal(&key2),
            "Two independently generated keys should not be identical"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_from_bytes() {
        let bytes = [0x42u8; AesGcm256Key::SIZE];

        let key = AesGcm256Key::from_bytes(bytes);

        assert_eq!(
            key.size(),
            AesGcm256Key::SIZE,
            "Key created from bytes must have the correct size"
        );

        let same_key = AesGcm256Key::from_bytes(bytes);

        assert!(
            key.is_equal(&same_key),
            "Keys created from identical bytes should be equal"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_from_bytes_different_keys() {
        let key1 = AesGcm256Key::from_bytes([0x00u8; AesGcm256Key::SIZE]);
        let key2 = AesGcm256Key::from_bytes([0xFFu8; AesGcm256Key::SIZE]);

        assert!(
            !key1.is_equal(&key2),
            "Keys containing different bytes should not be equal"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_try_from_bytes_valid() {
        let bytes = [0xABu8; AesGcm256Key::SIZE];

        let key = AesGcm256Key::try_from_bytes(&bytes).expect("32-byte key should be accepted");

        assert_eq!(
            key.size(),
            AesGcm256Key::SIZE,
            "Valid key must have the AES-256 key size"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_try_from_bytes_invalid_size() {
        let invalid_sizes = [0usize, 1, 16, 31, 33, 64];

        for size in invalid_sizes {
            let bytes = vec![0u8; size];

            let result = AesGcm256Key::try_from_bytes(&bytes);

            assert!(
                matches!(result, Err(CryptoError::InvalidKeySize)),
                "Expected InvalidKeySize for {} bytes, got: {result:?}",
                size
            );
        }
    }

    #[test]
    fn test_aes_gcm_256_key_try_from_slice_trait() {
        let bytes = [0x11u8; AesGcm256Key::SIZE];

        let key = AesGcm256Key::try_from(bytes.as_slice())
            .expect("TryFrom<&[u8]> should accept a 32-byte slice");

        let expected = AesGcm256Key::from_bytes(bytes);

        assert!(
            key.is_equal(&expected),
            "TryFrom<&[u8]> should preserve the key material"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_try_from_str_valid_base64() {
        let bytes = [0x55u8; AesGcm256Key::SIZE];

        let encoded = general_purpose::STANDARD.encode(bytes);

        let key = AesGcm256Key::try_from(encoded.as_str())
            .expect("Valid Base64 AES-256 key should be accepted");

        let expected = AesGcm256Key::from_bytes(bytes);

        assert!(
            key.is_equal(&expected),
            "Decoded Base64 key should match the original bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_from_base64_valid() {
        let bytes = [0xA5u8; AesGcm256Key::SIZE];

        let encoded = general_purpose::STANDARD.encode(bytes);

        let key = AesGcm256Key::from_base64(&encoded).expect("Valid Base64 key should be accepted");

        let expected = AesGcm256Key::from_bytes(bytes);

        assert!(
            key.is_equal(&expected),
            "Base64 decoding should preserve the key material"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_from_base64_invalid_encoding() {
        let result = AesGcm256Key::from_base64("not-valid-base64!!!");

        assert!(
            matches!(result, Err(CryptoError::InvalidBase64(_))),
            "Expected InvalidBase64, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_from_base64_invalid_key_size() {
        let invalid_key = [0x42u8; 16];

        let encoded = general_purpose::STANDARD.encode(invalid_key);

        let result = AesGcm256Key::from_base64(&encoded);

        assert!(
            matches!(result, Err(CryptoError::InvalidKeySize)),
            "Expected InvalidKeySize, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_debug_is_redacted() {
        let key = AesGcm256Key::from_bytes([0xAAu8; AesGcm256Key::SIZE]);

        let debug = format!("{key:?}");

        assert!(
            debug.contains("AesGcm256Key"),
            "Debug output should identify the key type"
        );

        assert!(
            debug.contains("[REDACTED]"),
            "Debug output must redact key material"
        );

        assert!(
            !debug.contains("aa"),
            "Debug output must not expose hexadecimal key material"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_equality_is_consistent() {
        let bytes = [0x7Fu8; AesGcm256Key::SIZE];

        let key1 = AesGcm256Key::from_bytes(bytes);
        let key2 = AesGcm256Key::from_bytes(bytes);
        let key3 = AesGcm256Key::from_bytes([0x80u8; AesGcm256Key::SIZE]);

        assert!(key1.is_equal(&key1), "A key must be equal to itself");

        assert!(
            key1.is_equal(&key2),
            "Keys with identical material must be equal"
        );

        assert!(key2.is_equal(&key1), "Key equality should be symmetric");

        assert!(
            !key1.is_equal(&key3),
            "Keys with different material must not be equal"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_partial_eq() {
        let key1 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key2 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key3 = AesGcm256Key::from_bytes([0x43u8; AesGcm256Key::SIZE]);

        assert_eq!(key1, key2);
        assert_ne!(key1, key3);
    }

    #[test]
    fn test_aes_gcm_256_key_eq_is_reflexive_and_symmetric() {
        let key1 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key2 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);

        assert_eq!(key1, key1);
        assert_eq!(key1, key2);
        assert_eq!(key2, key1);
    }

    #[test]
    fn test_aes_gcm_256_key_eq_is_transitive() {
        let key1 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key2 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key3 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);

        assert_eq!(key1, key2);
        assert_eq!(key2, key3);
        assert_eq!(key1, key3);
    }

    #[test]
    fn test_aes_gcm_256_key_partial_eq_matches_constant_time_equality() {
        let key1 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key2 = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let key3 = AesGcm256Key::from_bytes([0x43u8; AesGcm256Key::SIZE]);

        assert_eq!(
            key1 == key2,
            key1.is_equal(&key2),
            "PartialEq and is_equal must produce the same result"
        );

        assert_eq!(
            key1 == key3,
            key1.is_equal(&key3),
            "PartialEq and is_equal must produce the same result"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_eq_does_not_depend_on_object_identity() {
        let bytes = [0xABu8; AesGcm256Key::SIZE];

        let key1 = AesGcm256Key::from_bytes(bytes);
        let key2 = AesGcm256Key::from_bytes(bytes);

        assert_eq!(key1, key2, "Keys with identical key material must be equal");
    }

    #[test]
    fn test_aes_gcm_256_key_clone_preserves_key_material() {
        let key = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);

        let cloned_key = key.clone();

        assert_eq!(
            key, cloned_key,
            "Cloned key must contain the same key material"
        );

        assert!(
            key.is_equal(&cloned_key),
            "Cloned key must be equal to the original key"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_clone_is_independent() {
        let key = AesGcm256Key::from_bytes([0x42u8; AesGcm256Key::SIZE]);
        let cloned_key = key.clone();
        let different_key = AesGcm256Key::from_bytes([0x43u8; AesGcm256Key::SIZE]);

        assert_eq!(key, cloned_key);
        assert_ne!(cloned_key, different_key);
        assert_ne!(key, different_key);
    }
}
