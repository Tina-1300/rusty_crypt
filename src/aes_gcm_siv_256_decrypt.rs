use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce};
use std::convert::TryFrom;

use crate::error::CryptoError;

use super::aes_gcm_siv_256_key::AesGcmSiv256Key;
use super::aes_gcm_siv_256_nonce::AesGcmSiv256Nonce;

/// AES-256-GCM decryptor.
///
/// # Example
/// ```rust
/// use rusty_crypt::{AesGcmSivDecrypt, AesGcmSivEncrypt, AesGcmSivGeneratedNonce, AesGeneratedKey};
///
/// let key = AesGeneratedKey.generate_key().unwrap();
/// let nonce_gen = AesGcmSivGeneratedNonce;
/// let encryptor = AesGcmSivEncrypt::new(&nonce_gen, &key).unwrap();
/// let decryptor = AesGcmSivDecrypt::new(&key).unwrap();
///
/// let (ciphertext, nonce) = encryptor.encrypt_bytes(b"Secret").unwrap();
/// let plaintext = decryptor.decrypt_bytes(&ciphertext, &nonce).unwrap();
///
/// assert_eq!(plaintext, b"Secret");
/// ```
pub struct AesGcmSivDecrypt {
    cipher: Aes256GcmSiv,
}

impl AesGcmSivDecrypt {
    /// Creates a new AES-256-GCM decryptor from the given key.
    pub fn new(key: &AesGcmSiv256Key) -> Result<Self, CryptoError> {
        let cipher = Aes256GcmSiv::new_from_slice(key.as_bytes())
            .map_err(|_| CryptoError::InvalidKeySize)?;

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
        nonce: &AesGcmSiv256Nonce,
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
