#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose};
    use rusty_crypt::aes_gcm_256_decrypt::AesGcmDecrypt;
    use rusty_crypt::aes_gcm_256_encrypt::AesGcmEncrypt;
    use rusty_crypt::aes_gcm_256_generated_key::AesGeneratedKey;
    use rusty_crypt::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;

    #[test]
    fn test_checked_good_encryption_decryption() {
        let message = "ceci est un test vous ne pourrez pas me retrouvez";

        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        let nonce = AesGcmGeneratedNonce;

        let encrypt_aes = AesGcmEncrypt::new(&nonce);

        let decrypt_aes = AesGcmDecrypt;

        let key_b64 = general_purpose::STANDARD.encode(key);

        let message_cipher = encrypt_aes
            .encrypt(message, &key_b64)
            .expect("Encryption should succeed");

        assert_ne!(message, message_cipher);

        let result = decrypt_aes
            .decrypt(&message_cipher, &key_b64)
            .expect("Decryption should succeed");

        assert_eq!(message, result);
    }

    #[test]
    fn test_checked_good_encryption_decryption_full_bytes_version() {
        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        let nonce_gen = AesGcmGeneratedNonce;

        let encryptor = AesGcmEncrypt::new(&nonce_gen);

        let decryptor = AesGcmDecrypt;

        let message = b"Hello AES-256-GCM in bytes!";

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(message, &key)
            .expect("Encryption should succeed");

        let mut full_cipher = Vec::new();

        full_cipher.extend_from_slice(&nonce);

        full_cipher.extend_from_slice(&ciphertext);

        let decrypted = decryptor
            .decrypt_bytes(&full_cipher, &key)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, message);
    }
}
