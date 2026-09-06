use zeroize::Zeroizing;

use crate::{aes_gcm_256_key::AesGcm256Key, error::CryptoError};

/// Generates cryptographically secure AES-256 keys.
pub struct AesGeneratedKey;

impl AesGeneratedKey {
    /// Generates a random AES-256 key using the operating system's
    /// cryptographically secure random number generator.
    pub fn generate_key(&self) -> Result<AesGcm256Key, CryptoError> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *key).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(AesGcm256Key::from_zeroizing(key))
    }
}
