use crate::{aes_gcm_siv_256_nonce::AesGcmSiv256Nonce, error::CryptoError};

/// Generates cryptographically secure AES-GCM nonces.
///
/// # Example
/// ```rust
/// use rusty_crypt::AesGcmSivGeneratedNonce;
///
/// let generator = AesGcmSivGeneratedNonce;
/// let nonce = generator.generate_nonce().unwrap();
///
/// assert_eq!(nonce.size(), 12);
/// ```
pub struct AesGcmSivGeneratedNonce;

impl AesGcmSivGeneratedNonce {
    /// Generates a new cryptographically secure 96-bit nonce.
    ///
    /// A new nonce must be generated for every encryption
    /// performed with the same AES-GCM key.
    pub fn generate_nonce(&self) -> Result<AesGcmSiv256Nonce, CryptoError> {
        let mut bytes = [0u8; AesGcmSiv256Nonce::SIZE];

        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(AesGcmSiv256Nonce::from_bytes(bytes))
    }
}
