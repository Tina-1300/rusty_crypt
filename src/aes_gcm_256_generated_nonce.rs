use crate::{aes_gcm_256_nonce::AesGcm256Nonce, error::CryptoError};

/// Generates cryptographically secure AES-GCM nonces.
pub struct AesGcmGeneratedNonce;

impl AesGcmGeneratedNonce {
    /// Generates a new cryptographically secure 96-bit nonce.
    ///
    /// A new nonce must be generated for every encryption
    /// performed with the same AES-GCM key.
    pub fn generate_nonce(&self) -> Result<AesGcm256Nonce, CryptoError> {
        let mut bytes = [0u8; AesGcm256Nonce::SIZE];

        getrandom::fill(&mut bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(AesGcm256Nonce::from_bytes(bytes))
    }
}
