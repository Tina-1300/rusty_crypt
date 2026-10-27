use zeroize::Zeroizing;

use crate::{aes_gcm_siv_256_key::AesGcmSiv256Key, error::CryptoError};

/// Generates cryptographically secure AES-256 keys.
///
/// # Example
/// ```rust
/// use rusty_crypt::AesGeneratedKey;
///
/// let generator = AesGeneratedKey;
/// let key = generator.generate_key().unwrap();
///
/// assert_eq!(key.size(), 32);
/// ```
pub struct AesGeneratedKey;

impl AesGeneratedKey {
    /// Generates a random AES-256 key using the operating system's
    /// cryptographically secure random number generator.
    pub fn generate_key(&self) -> Result<AesGcmSiv256Key, CryptoError> {
        let mut key = Zeroizing::new([0u8; 32]);
        getrandom::fill(&mut *key).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(AesGcmSiv256Key::from_zeroizing(key))
    }
}
