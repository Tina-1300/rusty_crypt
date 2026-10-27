use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use std::convert::TryFrom;

use crate::error::CryptoError;

use super::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;
use super::aes_gcm_siv_256_key::AesGcmSiv256Key;
use super::aes_gcm_siv_256_nonce::AesGcmSiv256Nonce;

/// AES-256-GCM encryptor.
pub struct AesGcmEncrypt<'a> {
    cipher: Aes256GcmSiv,
    nonce_generator: &'a AesGcmGeneratedNonce,
}

impl<'a> AesGcmEncrypt<'a> {
    /// Creates a new AES-256-GCM encryptor.
    pub fn new(
        nonce_generator: &'a AesGcmGeneratedNonce,
        key: &'a AesGcmSiv256Key,
    ) -> Result<Self, CryptoError> {
        let cipher = Aes256GcmSiv::new_from_slice(key.as_bytes())
            .map_err(|_| CryptoError::InvalidKeySize)?;

        Ok(Self {
            cipher,
            nonce_generator,
        })
    }

    /// Encrypts plaintext using AES-256-GCM.
    ///
    /// Returns the ciphertext, including the authentication tag,
    /// and the nonce used for encryption.
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[inline]
    pub fn encrypt_bytes(
        &self,
        plaintext: &[u8],
    ) -> Result<(Vec<u8>, AesGcmSiv256Nonce), CryptoError> {
        let nonce = self.nonce_generator.generate_nonce()?;

        let nonce_bytes = *nonce.as_bytes();

        let nonce_ref = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError::InvalidNonceSize)?;

        let ciphertext = self
            .cipher
            .encrypt(&nonce_ref, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok((ciphertext, nonce))
    }
}
