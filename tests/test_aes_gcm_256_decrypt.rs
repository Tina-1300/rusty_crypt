#[cfg(test)]
mod tests {

    use base64::{Engine as _, engine::general_purpose};

    use rusty_crypt::aes_gcm_256_decrypt::AesGcmDecrypt;
    use rusty_crypt::error::CryptoError;

    #[test]
    fn test_aes_gcm_256_decrypt_valid_ciphertext() {
        let decryptor = AesGcmDecrypt;

        let key = "JeAe64TzfRKY0f4Mfx4slwqE3dZwQAXKd7UPZ2JF2q0=";

        let encrypted = "afRuT4pTzTXOhN8W::HUlMxpds+L3Vvy6PJlvdIQHkTvF/MjAgALYEBPADneIAkg==";

        let result = decryptor
            .decrypt(encrypted, key)
            .expect("Decryption should succeed");

        assert_eq!(result, "Hello rusty_crypt!");
    }

    #[test]
    fn test_aes_gcm_256_decrypt_wrong_key() {
        let decryptor = AesGcmDecrypt;

        let encrypted = "afRuT4pTzTXOhN8W::HUlMxpds+L3Vvy6PJlvdIQHkTvF/MjAgALYEBPADneIAkg==";

        let wrong_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

        let result = decryptor.decrypt(encrypted, wrong_key);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Wrong key should fail"
        );
    }

    #[test]
    fn test_aes_gcm_256_decrypt_invalid_ciphertext_format() {
        let decryptor = AesGcmDecrypt;

        let key = "JeAe64TzfRKY0f4Mfx4slwqE3dZwQAXKd7UPZ2JF2q0=";

        let encrypted = "invalid_ciphertext";

        let result = decryptor.decrypt(encrypted, key);

        assert!(matches!(result, Err(CryptoError::InvalidCiphertext)));
    }

    #[test]
    fn test_aes_gcm_256_decrypt_invalid_base64() {
        let decryptor = AesGcmDecrypt;

        let key = "not_valid_base64!!!";

        let encrypted = "afRuT4pTzTXOhN8W::HUlMxpds+L3Vvy6PJlvdIQHkTvF/MjAgALYEBPADneIAkg==";

        let result = decryptor.decrypt(encrypted, key);

        assert!(matches!(result, Err(CryptoError::InvalidBase64(_))));
    }

    #[test]
    fn test_aes_gcm_256_decrypt_invalid_key_size() {
        let decryptor = AesGcmDecrypt;

        let short_key = general_purpose::STANDARD.encode(vec![0u8; 16]);

        let encrypted = "afRuT4pTzTXOhN8W::HUlMxpds+L3Vvy6PJlvdIQHkTvF/MjAgALYEBPADneIAkg==";

        let result = decryptor.decrypt(encrypted, &short_key);

        assert!(matches!(result, Err(CryptoError::InvalidKeySize)));
    }
}
