use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use std::convert::TryFrom;

use crate::error::CryptoError;

use super::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;
use super::aes_gcm_256_key::AesGcm256Key;
use super::aes_gcm_256_nonce::AesGcm256Nonce;

/// High-level AES-256-GCM cipher.
///
/// Owns the AES-256 key and keeps the AES-GCM cipher initialized
/// for reuse across encryption and decryption operations.
///
/// A fresh cryptographically secure nonce is generated for every
/// encryption operation.
pub struct AesGcm256 {
    key: AesGcm256Key,
    cipher: Aes256Gcm,
    nonce_generator: AesGcmGeneratedNonce,
}

impl AesGcm256 {
    /// Creates a new AES-256-GCM cipher from the given key.
    ///
    /// The AES-GCM cipher is initialized once and reused for all
    /// subsequent encryption and decryption operations.
    #[inline]
    pub fn new(key: AesGcm256Key) -> Self {
        let cipher = Aes256Gcm::new(key.as_key());

        Self {
            key,
            cipher,
            nonce_generator: AesGcmGeneratedNonce,
        }
    }

    /// Encrypts plaintext using AES-256-GCM.
    ///
    /// A fresh cryptographically secure nonce is generated for every
    /// encryption operation.
    ///
    /// Returns the ciphertext, including the authentication tag,
    /// together with the nonce required for decryption.
    #[inline]
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<(Vec<u8>, AesGcm256Nonce), CryptoError> {
        let nonce = self.nonce_generator.generate_nonce()?;

        let nonce_ref = Nonce::try_from(nonce.as_bytes().as_slice())
            .map_err(|_| CryptoError::InvalidNonceSize)?;

        let ciphertext = self
            .cipher
            .encrypt(&nonce_ref, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok((ciphertext, nonce))
    }

    /// Decrypts AES-256-GCM ciphertext.
    ///
    /// The ciphertext must contain the 16-byte authentication tag.
    ///
    /// The supplied nonce must be the nonce used during encryption.
    #[inline]
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce: &AesGcm256Nonce,
    ) -> Result<Vec<u8>, CryptoError> {
        if ciphertext.len() < 16 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let nonce_ref = Nonce::try_from(nonce.as_bytes().as_slice())
            .map_err(|_| CryptoError::InvalidNonceSize)?;

        self.cipher
            .decrypt(&nonce_ref, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }

    /// Returns a reference to the protected AES-256 key.
    #[inline]
    pub fn key(&self) -> &AesGcm256Key {
        &self.key
    }
}
