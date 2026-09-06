#[cfg(test)]
mod tests {
    use rusty_crypt::{AesGcm256Nonce, CryptoError};

    #[test]
    fn test_aes_gcm_256_nonce_size() {
        assert_eq!(
            AesGcm256Nonce::SIZE,
            12,
            "AES-GCM nonce size must be 12 bytes"
        );

        let nonce = AesGcm256Nonce::from_bytes([0u8; AesGcm256Nonce::SIZE]);

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Nonce size should match AesGcm256Nonce::SIZE"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_from_bytes_preserves_data() {
        let bytes = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B,
        ];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        assert_eq!(
            nonce.as_ref(),
            &bytes,
            "Nonce should preserve the original bytes"
        );

        assert_eq!(
            nonce.as_slice(),
            &bytes,
            "as_slice() should return the original nonce bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_try_from_bytes_valid() {
        let bytes = [0x42u8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::try_from_bytes(&bytes)
            .expect("A 12-byte slice should produce a valid nonce");

        assert_eq!(
            nonce.as_slice(),
            &bytes,
            "Valid nonce bytes should be preserved"
        );

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Valid nonce should have the expected size"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_try_from_bytes_invalid_sizes() {
        let invalid_sizes = [0usize, 1, 11, 13, 16, 32];

        for size in invalid_sizes {
            let bytes = vec![0u8; size];

            let result = AesGcm256Nonce::try_from_bytes(&bytes);

            assert!(
                matches!(result, Err(CryptoError::InvalidNonceSize)),
                "Expected InvalidNonceSize for {} bytes, got: {result:?}",
                size
            );
        }
    }

    #[test]
    fn test_aes_gcm_256_nonce_try_from_slice_trait() {
        let bytes = [0xABu8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::try_from(bytes.as_slice())
            .expect("TryFrom<&[u8]> should accept a 12-byte slice");

        assert_eq!(
            nonce.as_slice(),
            &bytes,
            "TryFrom<&[u8]> should preserve the nonce bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_from_array_trait() {
        let bytes = [0xCDu8; AesGcm256Nonce::SIZE];

        let nonce: AesGcm256Nonce = bytes.into();

        assert_eq!(
            nonce.as_slice(),
            &bytes,
            "From<[u8; 12]> should preserve the nonce bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_into_bytes() {
        let bytes = [
            0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xA0, 0xB0, 0xC0,
        ];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        let recovered = nonce.into_bytes();

        assert_eq!(
            recovered, bytes,
            "into_bytes() should return the original nonce bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_as_ref() {
        let bytes = [0x55u8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        let nonce_ref: &[u8] = nonce.as_ref();

        assert_eq!(
            nonce_ref.len(),
            AesGcm256Nonce::SIZE,
            "AsRef<[u8]> should return exactly 12 bytes"
        );

        assert_eq!(
            nonce_ref, &bytes,
            "AsRef<[u8]> should expose the nonce bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_as_slice() {
        let bytes = [0x77u8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        assert_eq!(
            nonce.as_slice().len(),
            AesGcm256Nonce::SIZE,
            "as_slice() should return exactly 12 bytes"
        );

        assert_eq!(
            nonce.as_slice(),
            &bytes,
            "as_slice() should return the underlying nonce"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_equality() {
        let bytes = [0x11u8; AesGcm256Nonce::SIZE];

        let nonce1 = AesGcm256Nonce::from_bytes(bytes);
        let nonce2 = AesGcm256Nonce::from_bytes(bytes);
        let nonce3 = AesGcm256Nonce::from_bytes([0x22u8; AesGcm256Nonce::SIZE]);

        assert_eq!(
            nonce1, nonce2,
            "Nonces with identical bytes should be equal"
        );

        assert_ne!(
            nonce1, nonce3,
            "Nonces with different bytes should not be equal"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_copy_and_clone() {
        let bytes = [0x99u8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        let copied = nonce;
        let cloned = nonce;

        assert_eq!(copied, nonce, "Nonce should implement Copy");

        assert_eq!(cloned, nonce, "Nonce should implement Clone");
    }

    #[test]
    fn test_aes_gcm_256_nonce_hash_consistency() {
        use std::collections::HashSet;

        let bytes = [0x42u8; AesGcm256Nonce::SIZE];

        let nonce1 = AesGcm256Nonce::from_bytes(bytes);
        let nonce2 = AesGcm256Nonce::from_bytes(bytes);

        let mut set = HashSet::new();

        set.insert(nonce1);

        assert!(
            set.contains(&nonce2),
            "Equal nonces should produce compatible hashes"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_debug_contains_value() {
        let bytes = [0xABu8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        let debug = format!("{nonce:?}");

        assert!(
            debug.contains("AesGcm256Nonce"),
            "Debug output should identify the nonce type"
        );

        assert!(
            debug.contains("ab"),
            "Debug output should contain the nonce representation"
        );
    }
}
