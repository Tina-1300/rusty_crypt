use crate::error::CryptoError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose};

pub struct AesGcmDecrypt;

impl AesGcmDecrypt {
    pub fn decrypt(
        &self,
        base64_cipher_text: &str,
        base64_key: &str,
    ) -> Result<String, CryptoError> {
        let parts: Vec<&str> = base64_cipher_text.split("::").collect();

        if parts.len() != 2 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(CryptoError::InvalidBase64)?;

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let nonce_bytes = general_purpose::STANDARD
            .decode(parts[0])
            .map_err(CryptoError::InvalidBase64)?;

        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonceSize);
        }

        let ciphertext = general_purpose::STANDARD
            .decode(parts[1])
            .map_err(CryptoError::InvalidBase64)?;

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(&nonce_bytes);

        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let text = String::from_utf8(decrypted).map_err(CryptoError::InvalidUtf8)?;

        Ok(text)
    }

    pub fn decrypt_bytes(
        &self,
        cipher_bytes: &[u8],
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if cipher_bytes.len() < 12 {
            return Err(CryptoError::InvalidCiphertext);
        }

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let (nonce_bytes, ciphertext) = cipher_bytes.split_at(12);

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);

        let cipher = Aes256Gcm::new(key);

        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
