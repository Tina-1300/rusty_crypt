#[cfg(test)]
mod tests {
    use rusty_crypt::{
        AesGcm256Nonce, AesGcmDecrypt, AesGcmEncrypt, AesGcmGeneratedNonce, AesGeneratedKey,
        CryptoError,
    };

    fn create_encryptor<'a>(
        key: &'a rusty_crypt::AesGcm256Key,
        nonce_generator: &'a AesGcmGeneratedNonce,
    ) -> AesGcmEncrypt<'a> {
        AesGcmEncrypt::new(nonce_generator, key).expect("Encryptor should be created")
    }

    fn create_decryptor(key: &rusty_crypt::AesGcm256Key) -> AesGcmDecrypt {
        AesGcmDecrypt::new(key).expect("Decryptor should be created")
    }

    #[test]
    fn test_aes_gcm_256_encryption_decryption() {
        let plaintext = b"ceci est un test vous ne pourrez pas me retrouver";

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let decryptor = create_decryptor(&key);

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Encryption should succeed");

        assert_ne!(
            ciphertext, plaintext,
            "Ciphertext must differ from plaintext"
        );

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Generated nonce must have the AES-GCM size"
        );

        let decrypted = decryptor
            .decrypt_bytes(&ciphertext, &nonce)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted plaintext must match the original plaintext"
        );
    }

    #[test]
    fn test_aes_gcm_256_encryption_decryption_full_bytes() {
        let plaintext = [
            0x00, 0x01, 0x02, 0x03, 0x10, 0x20, 0x30, 0x40, 0x80, 0x81, 0xfe, 0xff,
        ];

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let decryptor = create_decryptor(&key);

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(&plaintext)
            .expect("Binary data encryption should succeed");

        let decrypted = decryptor
            .decrypt_bytes(&ciphertext, &nonce)
            .expect("Binary data decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Binary plaintext must survive encryption and decryption unchanged"
        );
    }

    #[test]
    fn test_aes_gcm_256_encryption_decryption_empty_message() {
        let plaintext: &[u8] = b"";

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let decryptor = create_decryptor(&key);

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Empty plaintext encryption should succeed");

        assert_eq!(
            ciphertext.len(),
            16,
            "AES-GCM empty plaintext must produce a 16-byte authentication tag"
        );

        let decrypted = decryptor
            .decrypt_bytes(&ciphertext, &nonce)
            .expect("Empty plaintext decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Empty plaintext must decrypt back to an empty message"
        );
    }

    #[test]
    fn test_aes_gcm_256_encryption_generates_unique_nonces() {
        let plaintext = b"same plaintext";

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let (ciphertext_1, nonce_1) = encryptor
            .encrypt_bytes(plaintext)
            .expect("First encryption should succeed");

        let (ciphertext_2, nonce_2) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Second encryption should succeed");

        assert_ne!(
            nonce_1, nonce_2,
            "Encryptions with the same key must use different nonces"
        );

        assert_ne!(
            ciphertext_1, ciphertext_2,
            "Same plaintext encrypted with different nonces should produce different ciphertexts"
        );
    }

    #[test]
    fn test_aes_gcm_256_decryption_fails_with_different_key() {
        let plaintext = b"secret message";

        let encryption_key = AesGeneratedKey
            .generate_key()
            .expect("Encryption key generation should succeed");

        let decryption_key = AesGeneratedKey
            .generate_key()
            .expect("Decryption key generation should succeed");

        assert!(
            !encryption_key.is_equal(&decryption_key),
            "Generated keys should normally be different"
        );

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&encryption_key, &nonce_generator);

        let decryptor = create_decryptor(&decryption_key);

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Encryption should succeed");

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Decryption with another key should fail, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_decryption_fails_with_modified_ciphertext() {
        let plaintext = b"authenticated message";

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let decryptor = create_decryptor(&key);

        let (mut ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Encryption should succeed");

        assert!(
            !ciphertext.is_empty(),
            "AES-GCM ciphertext should not be empty"
        );

        ciphertext[0] ^= 0x01;

        let result = decryptor.decrypt_bytes(&ciphertext, &nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Modified ciphertext must fail authentication, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_decryption_fails_with_modified_nonce() {
        let plaintext = b"authenticated message";

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let decryptor = create_decryptor(&key);

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Encryption should succeed");

        let mut nonce_bytes = nonce.into_bytes();

        nonce_bytes[0] ^= 0x01;

        let modified_nonce = AesGcm256Nonce::from_bytes(nonce_bytes);

        let result = decryptor.decrypt_bytes(&ciphertext, &modified_nonce);

        assert!(
            matches!(result, Err(CryptoError::DecryptionFailed)),
            "Modified nonce must fail authentication, got: {result:?}"
        );
    }

    #[test]
    fn test_aes_gcm_256_multiple_messages_roundtrip() {
        let messages: &[&[u8]] = &[
            b"short",
            b"Hello AES-256-GCM!",
            b"",
            b"A longer message used to verify that the encryption and decryption pipeline works correctly.",
            &[0x00, 0x01, 0x02, 0xfe, 0xff],
        ];

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        let decryptor = create_decryptor(&key);

        for message in messages {
            let (ciphertext, nonce) = encryptor
                .encrypt_bytes(message)
                .expect("Encryption should succeed");

            let decrypted = decryptor
                .decrypt_bytes(&ciphertext, &nonce)
                .expect("Decryption should succeed");

            assert_eq!(
                decrypted, *message,
                "Every plaintext must round-trip correctly"
            );
        }
    }

    #[test]
    fn test_aes_gcm_256_ciphertext_size() {
        let messages: &[&[u8]] = &[
            b"",
            b"a",
            b"hello",
            b"Hello AES-256-GCM!",
            &[0u8; 32],
            &[0u8; 128],
        ];

        let key = AesGeneratedKey
            .generate_key()
            .expect("AES-256 key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor = create_encryptor(&key, &nonce_generator);

        for plaintext in messages {
            let (ciphertext, _) = encryptor
                .encrypt_bytes(plaintext)
                .expect("Encryption should succeed");

            assert_eq!(
                ciphertext.len(),
                plaintext.len() + 16,
                "AES-GCM ciphertext should contain plaintext plus the 16-byte authentication tag"
            );
        }
    }
}
