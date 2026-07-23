use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose};

use crate::error::CryptoError;

use super::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;

pub struct AesGcmEncrypt<'a> {
    nonce_generator: &'a AesGcmGeneratedNonce,
}

impl<'a> AesGcmEncrypt<'a> {
    pub fn new(nonce_generator: &'a AesGcmGeneratedNonce) -> Self {
        Self { nonce_generator }
    }

    pub fn encrypt(&self, plaintext: &str, base64_key: &str) -> Result<String, CryptoError> {
        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(CryptoError::InvalidBase64)?;

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        let cipher = Aes256Gcm::new(key);

        let nonce_bytes = self.nonce_generator.generate_nonce();

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext);

        let nonce_base64 = general_purpose::STANDARD.encode(nonce_bytes);

        Ok(format!("{nonce_base64}::{ciphertext_base64}"))
    }

    pub fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        key_bytes: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);

        let cipher = Aes256Gcm::new(key);

        let nonce_bytes = self.nonce_generator.generate_nonce();

        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok((ciphertext, nonce_bytes))
    }
}

/*

use rusty_crypt::{
    AesGeneratedKey, AesGcmGeneratedNonce,
    AesGcmEncrypt, AesGcmDecrypt,
};

fn main() {
    let key_gen = AesGeneratedKey;
    let key = key_gen.generate_key();

    let nonce_gen = AesGcmGeneratedNonce;
    let encryptor = AesGcmEncrypt::new(&nonce_gen);
    let decryptor = AesGcmDecrypt;

    let message = b"Hello AES-256-GCM in bytes!";

    // Encrypt
    let (ciphertext, nonce) = encryptor.encrypt_bytes(message, &key);

    // Concat nonce + ciphertext pour transmettre
    let mut full_cipher = Vec::new();
    full_cipher.extend_from_slice(&nonce);
    full_cipher.extend_from_slice(&ciphertext);

    // Decrypt
    let decrypted = decryptor.decrypt_bytes(&full_cipher, &key);

    assert_eq!(decrypted, message);
    println!("Decrypted message: {:?}", String::from_utf8(decrypted).unwrap());
}


*/
