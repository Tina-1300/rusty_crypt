#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose};

    use rusty_crypt::{AesGcm256Key, AesGcm256Nonce, AesGcmDecrypt, CryptoError};

    const VALID_KEY_BASE64: &str = "JeAe64TzfRKY0f4Mfx4slwqE3dZwQAXKd7UPZ2JF2q0=";

    const WRONG_KEY_BASE64: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    const ENCRYPTED_MESSAGE: &str =
        "afRuT4pTzTXOhN8W::HUlMxpds+L3Vvy6PJlvdIQHkTvF/MjAgALYEBPADneIAkg==";

    const EXPECTED_PLAINTEXT: &[u8] = b"Hello rusty_crypt!";

    fn valid_key() -> AesGcm256Key {
        AesGcm256Key::from_base64(VALID_KEY_BASE64).expect("Test key should be valid")
    }

    fn wrong_key() -> AesGcm256Key {
        AesGcm256Key::from_base64(WRONG_KEY_BASE64).expect("Test key should be valid")
    }

    fn encrypted_parts() -> (AesGcm256Nonce, Vec<u8>) {
        let (nonce_base64, ciphertext_base64) = ENCRYPTED_MESSAGE
            .split_once("::")
            .expect("Encrypted value should contain ::");

        let nonce_bytes = general_purpose::STANDARD
            .decode(nonce_base64)
            .expect("Nonce should be valid Base64");

        let nonce = AesGcm256Nonce::try_from_bytes(&nonce_bytes)
            .expect("Nonce should contain exactly 12 bytes");

        let ciphertext = general_purpose::STANDARD
            .decode(ciphertext_base64)
            .expect("Ciphertext should be valid Base64");

        (nonce, ciphertext)
    }

    #[test]
    fn test_aes_gcm_256_decrypt_valid_ciphertext() {
        let key = valid_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let (nonce, ciphertext) = encrypted_parts();

        let plaintext = decryptor
            .decrypt_bytes(&ciphertext, &nonce)
            .expect("Decryption should succeed");

        assert_eq!(
            plaintext, EXPECTED_PLAINTEXT,
            "Decrypted plaintext should match the original message"
        );
    }

    #[test]
    fn test_aes_gcm_256_decrypt_wrong_key() {
        let key = wrong_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let (nonce, ciphertext) = encrypted_parts();

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Wrong key should cause DecryptionFailed, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_decrypt_invalid_ciphertext() {
        let key = valid_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let ciphertext = [0u8; 15];
        let nonce = AesGcm256Nonce::from_bytes([0u8; AesGcm256Nonce::SIZE]);

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::InvalidCiphertext)),
            "Ciphertext shorter than 16 bytes should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_decrypt_invalid_ciphertext_authentication() {
        let key = valid_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let ciphertext = [0u8; 16];
        let nonce = AesGcm256Nonce::from_bytes([0u8; AesGcm256Nonce::SIZE]);

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Invalid authentication data should cause DecryptionFailed, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_decrypt_empty_ciphertext() {
        let key = valid_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let ciphertext: [u8; 0] = [];
        let nonce = AesGcm256Nonce::from_bytes([0u8; AesGcm256Nonce::SIZE]);

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::InvalidCiphertext)),
            "Empty ciphertext should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_invalid_nonce_size() {
        let result = AesGcm256Nonce::try_from_bytes(&[0u8; AesGcm256Nonce::SIZE - 1]);

        assert!(
            matches!(result, Err(CryptoError::InvalidNonceSize)),
            "11-byte nonce should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_nonce_roundtrip() {
        let bytes = [0x42u8; AesGcm256Nonce::SIZE];

        let nonce = AesGcm256Nonce::from_bytes(bytes);

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Nonce size should be 12 bytes"
        );

        assert_eq!(nonce.as_slice(), &bytes, "Nonce bytes should be preserved");

        assert_eq!(
            nonce.as_ref(),
            &bytes,
            "AsRef representation should match the original bytes"
        );

        assert_eq!(
            nonce.into_bytes(),
            bytes,
            "into_bytes should return the original nonce"
        );
    }

    #[test]
    fn test_aes_gcm_256_invalid_key_size() {
        let result = AesGcm256Key::try_from_bytes(&[0u8; AesGcm256Key::SIZE - 1]);

        assert!(
            matches!(result, Err(CryptoError::InvalidKeySize)),
            "31-byte key should be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_valid_key_size() {
        let bytes = [0x42u8; AesGcm256Key::SIZE];

        let key = AesGcm256Key::try_from_bytes(&bytes).expect("32-byte key should be valid");

        assert_eq!(
            key.size(),
            AesGcm256Key::SIZE,
            "AES-256 key must contain 32 bytes"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_base64_roundtrip() {
        let key = valid_key();

        let encoded = general_purpose::STANDARD.encode([0u8; AesGcm256Key::SIZE]);

        let decoded_key = AesGcm256Key::from_base64(&encoded)
            .expect("Valid Base64 AES-256 key should be accepted");

        assert!(
            key.size() == decoded_key.size(),
            "Decoded key should have the AES-256 key size"
        );
    }

    #[test]
    fn test_aes_gcm_256_invalid_base64_key() {
        let result = AesGcm256Key::from_base64("not-valid-base64!!!");

        assert!(
            matches!(result, Err(CryptoError::InvalidBase64(_))),
            "Invalid Base64 should return InvalidBase64, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_key_equality() {
        let bytes = [0x42u8; AesGcm256Key::SIZE];

        let key1 = AesGcm256Key::from_bytes(bytes);
        let key2 = AesGcm256Key::from_bytes(bytes);
        let key3 = AesGcm256Key::from_bytes([0x24u8; AesGcm256Key::SIZE]);

        assert!(key1.is_equal(&key2), "Identical keys should be equal");

        assert!(!key1.is_equal(&key3), "Different keys should not be equal");
    }

    #[test]
    fn test_aes_gcm_256_decrypt_with_modified_ciphertext() {
        let key = valid_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let (nonce, mut ciphertext) = encrypted_parts();

        // Modification d'un seul octet du ciphertext.
        ciphertext[0] ^= 0x01;

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Modified ciphertext should fail authentication, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_decrypt_with_modified_nonce() {
        let key = valid_key();
        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor should be created");

        let (nonce, ciphertext) = encrypted_parts();

        let mut nonce_bytes = nonce.into_bytes();

        nonce_bytes[0] ^= 0x01;

        let modified_nonce = AesGcm256Nonce::from_bytes(nonce_bytes);

        let result = decryptor.decrypt_bytes(&ciphertext, &modified_nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Modified nonce should fail authentication, got: {result:?}"
        );
    }
}
