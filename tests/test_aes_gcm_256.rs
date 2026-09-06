#[cfg(test)]
mod tests {
    use rusty_crypt::{AesGcm256, AesGcm256Key, AesGcm256Nonce, CryptoError};

    fn test_key() -> AesGcm256Key {
        AesGcm256Key::from_bytes([0x42; AesGcm256Key::SIZE])
    }

    #[test]
    fn test_aes_gcm_256_encrypt_decrypt() {
        let aes = AesGcm256::new(test_key());
        let plaintext = b"Hello rusty_crypt!";

        let (ciphertext, nonce) = aes.encrypt(plaintext).expect("Encryption should succeed");

        assert_ne!(
            ciphertext, plaintext,
            "Ciphertext should differ from plaintext"
        );

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Nonce should have the AES-GCM nonce size"
        );

        let decrypted = aes
            .decrypt(&ciphertext, &nonce)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted plaintext should match the original plaintext"
        );
    }

    #[test]
    fn test_aes_gcm_256_encrypt_empty_plaintext() {
        let aes = AesGcm256::new(test_key());

        let (ciphertext, nonce) = aes
            .encrypt(b"")
            .expect("Encryption of empty plaintext should succeed");

        assert_eq!(
            ciphertext.len(),
            16,
            "Empty plaintext should produce only the 16-byte authentication tag"
        );

        let decrypted = aes
            .decrypt(&ciphertext, &nonce)
            .expect("Decryption should succeed");

        assert!(
            decrypted.is_empty(),
            "Decrypted empty plaintext should be empty"
        );
    }

    #[test]
    fn test_aes_gcm_256_generates_unique_nonces() {
        let aes = AesGcm256::new(test_key());
        let plaintext = b"same plaintext";

        let (ciphertext_1, nonce_1) = aes
            .encrypt(plaintext)
            .expect("First encryption should succeed");

        let (ciphertext_2, nonce_2) = aes
            .encrypt(plaintext)
            .expect("Second encryption should succeed");

        assert_ne!(
            nonce_1, nonce_2,
            "Each encryption should generate a fresh nonce"
        );

        assert_ne!(
            ciphertext_1, ciphertext_2,
            "Different nonces should produce different ciphertexts"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_accessor() {
        let key = test_key();
        let aes = AesGcm256::new(key);

        assert!(
            aes.key().is_equal(&test_key()),
            "AesGcm256::key should return the same key"
        );

        assert_eq!(
            aes.key().size(),
            AesGcm256Key::SIZE,
            "AES-256 key should contain 32 bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_wrong_key_fails_decryption() {
        let aes = AesGcm256::new(test_key());
        let plaintext = b"secret message";

        let (ciphertext, nonce) = aes.encrypt(plaintext).expect("Encryption should succeed");

        let wrong_key = AesGcm256Key::from_bytes([0x99; AesGcm256Key::SIZE]);
        let wrong_aes = AesGcm256::new(wrong_key);

        let result = wrong_aes.decrypt(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Decryption with a different key should fail"
        );
    }

    #[test]
    fn test_aes_gcm_256_tampered_ciphertext_fails() {
        let aes = AesGcm256::new(test_key());
        let plaintext = b"authenticated message";

        let (mut ciphertext, nonce) = aes.encrypt(plaintext).expect("Encryption should succeed");

        ciphertext[0] ^= 0x01;

        let result = aes.decrypt(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Tampering with ciphertext should invalidate authentication"
        );
    }

    #[test]
    fn test_aes_gcm_256_tampered_nonce_fails() {
        let aes = AesGcm256::new(test_key());
        let plaintext = b"authenticated message";

        let (ciphertext, nonce) = aes.encrypt(plaintext).expect("Encryption should succeed");

        let mut nonce_bytes = nonce.into_bytes();
        nonce_bytes[0] ^= 0x01;

        let tampered_nonce = AesGcm256Nonce::from_bytes(nonce_bytes);

        let result = aes.decrypt(&ciphertext, &tampered_nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Changing the nonce should invalidate authentication"
        );
    }

    #[test]
    fn test_aes_gcm_256_invalid_ciphertext_fails() {
        let aes = AesGcm256::new(test_key());
        let nonce = AesGcm256Nonce::from_bytes([0u8; AesGcm256Nonce::SIZE]);

        let result = aes.decrypt(&[0u8; 15], &nonce);

        assert!(
            matches!(result, Err(CryptoError::InvalidCiphertext)),
            "Ciphertext shorter than the authentication tag should be rejected"
        );
    }

    #[test]
    fn test_aes_gcm_256_binary_data_roundtrip() {
        let aes = AesGcm256::new(test_key());

        let plaintext: Vec<u8> = (0u8..=255).collect();

        let (ciphertext, nonce) = aes
            .encrypt(&plaintext)
            .expect("Binary data encryption should succeed");

        let decrypted = aes
            .decrypt(&ciphertext, &nonce)
            .expect("Binary data decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Arbitrary binary data should survive encryption/decryption"
        );
    }
}
