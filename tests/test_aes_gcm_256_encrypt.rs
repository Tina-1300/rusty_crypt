#[cfg(test)]
mod tests {
    use rusty_crypt::{
        AesGcm256Nonce, AesGcmDecrypt, AesGcmEncrypt, AesGcmGeneratedNonce, AesGeneratedKey,
    };

    #[test]
    fn test_aes_gcm_256_encryption_decryption() {
        let plaintext = b"ceci est un test vous ne pourrez pas me retrouver";

        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor =
            AesGcmEncrypt::new(&nonce_generator, &key).expect("Encryptor creation should succeed");

        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor creation should succeed");

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Encryption should succeed");

        assert_ne!(
            ciphertext, plaintext,
            "Ciphertext should differ from plaintext"
        );

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Nonce should have the AES-GCM nonce size"
        );

        assert_eq!(
            nonce.as_slice().len(),
            AesGcm256Nonce::SIZE,
            "Nonce should contain exactly 12 bytes"
        );

        assert_eq!(
            ciphertext.len(),
            plaintext.len() + 16,
            "Ciphertext should contain plaintext plus the authentication tag"
        );

        let decrypted = decryptor
            .decrypt_bytes(&ciphertext, &nonce)
            .expect("Decryption should succeed");

        assert_eq!(
            decrypted, plaintext,
            "Decrypted plaintext should match the original plaintext"
        );
    }

    #[test]
    fn test_aes_gcm_256_encryption_decryption_empty_message() {
        let plaintext = b"";

        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor =
            AesGcmEncrypt::new(&nonce_generator, &key).expect("Encryptor creation should succeed");

        let decryptor = AesGcmDecrypt::new(&key).expect("Decryptor creation should succeed");

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Encryption should succeed");

        assert_eq!(
            ciphertext.len(),
            16,
            "Empty plaintext should produce a 16-byte authentication tag"
        );

        assert_eq!(
            nonce.size(),
            AesGcm256Nonce::SIZE,
            "Nonce should have the AES-GCM nonce size"
        );

        let decrypted = decryptor
            .decrypt_bytes(&ciphertext, &nonce)
            .expect("Decryption should succeed");

        assert_eq!(decrypted, plaintext, "Decrypted plaintext should be empty");
    }

    #[test]
    fn test_aes_gcm_256_encryption_generates_different_nonces() {
        let plaintext = b"Hello AES-256-GCM!";

        let key = AesGeneratedKey
            .generate_key()
            .expect("Key generation should succeed");

        let nonce_generator = AesGcmGeneratedNonce;

        let encryptor =
            AesGcmEncrypt::new(&nonce_generator, &key).expect("Encryptor creation should succeed");

        let (_, nonce_1) = encryptor
            .encrypt_bytes(plaintext)
            .expect("First encryption should succeed");

        let (_, nonce_2) = encryptor
            .encrypt_bytes(plaintext)
            .expect("Second encryption should succeed");

        assert_ne!(
            nonce_1, nonce_2,
            "Each encryption should generate a different nonce"
        );
    }
}
