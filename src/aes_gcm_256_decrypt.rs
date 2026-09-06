use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use std::convert::TryFrom;

use crate::error::CryptoError;

use super::aes_gcm_256_key::AesGcm256Key;
use super::aes_gcm_256_nonce::AesGcm256Nonce;

/// AES-256-GCM decryptor.
pub struct AesGcmDecrypt {
    cipher: Aes256Gcm,
}

impl AesGcmDecrypt {
    /// Creates a new AES-256-GCM decryptor from the given key.
    pub fn new(key: &AesGcm256Key) -> Result<Self, CryptoError> {
        let cipher =
            Aes256Gcm::new_from_slice(key.as_bytes()).map_err(|_| CryptoError::InvalidKeySize)?;

        Ok(Self { cipher })
    }

    /// Decrypts ciphertext using the given AES-256-GCM nonce.
    ///
    /// The ciphertext must include its 16-byte authentication tag.
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[inline]
    pub fn decrypt_bytes(
        &self,
        ciphertext: &[u8],
        nonce: &AesGcm256Nonce,
    ) -> Result<Vec<u8>, CryptoError> {
        // AES-GCM requires a 16-byte authentication tag.
        if ciphertext.len() < 16 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce_bytes = *nonce.as_bytes();

        let nonce_ref = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError::InvalidNonceSize)?;

        self.cipher
            .decrypt(&nonce_ref, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
