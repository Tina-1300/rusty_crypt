use crate::error::CryptoError;

/// AES-256 secure key generator.
///
/// `AesGeneratedKey` provides a simple interface to generate cryptographically
/// secure random keys compatible with AES-256-GCM encryption.
///
/// AES-256 requires a key size of:
///
/// ```text
/// 32 bytes (256 bits)
/// ```
///
/// The key generation uses the operating system's secure random number
/// generator through [`getrandom`].
///
/// # Security
///
/// Generated keys are suitable for cryptographic usage:
///
/// - AES-256-GCM encryption
/// - File encryption
/// - Secure data storage
/// - Key wrapping systems
///
/// The generated key should be kept secret and should never be exposed
/// publicly.
///
/// # Example
///
/// Generate an AES-256 key:
///
/// ```rust
/// use rusty_crypt::AesGeneratedKey;
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///
///     let key_generator = AesGeneratedKey;
///
///     let key = key_generator.generate_key()?;
///
///     println!(
///         "Generated key size: {} bytes",
///         key.len()
///     );
///
///     assert_eq!(key.len(), 32);
///
///     Ok(())
/// }
/// ```
pub struct AesGeneratedKey;

impl AesGeneratedKey {
    /// Generates a new random AES-256 encryption key.
    ///
    /// This function creates a cryptographically secure random key
    /// with a fixed size of 32 bytes.
    ///
    /// The generated key can be directly used with:
    ///
    /// - [`AesGcmEncrypt::encrypt_bytes`](crate::AesGcmEncrypt::encrypt_bytes)
    /// - [`AesGcmDecrypt::decrypt_bytes`](crate::AesGcmDecrypt::decrypt_bytes)
    ///
    /// # Returns
    ///
    /// Returns:
    ///
    /// ```text
    /// [u8; 32]
    /// ```
    ///
    /// representing a 256-bit AES key.
    ///
    /// # Errors
    ///
    /// Returns:
    ///
    /// [`CryptoError::RandomGenerationFailed`]
    ///
    /// if the operating system secure random generator fails.
    ///
    /// # Example
    ///
    /// Generate a key and encrypt binary data:
    ///
    /// ```rust
    /// use rusty_crypt::{
    ///     AesGeneratedKey,
    ///     AesGcmEncrypt,
    ///     AesGcmGeneratedNonce,
    /// };
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    ///     let key =
    ///         AesGeneratedKey.generate_key()?;
    ///
    ///     let nonce =
    ///         AesGcmGeneratedNonce;
    ///
    ///     let encryptor =
    ///         AesGcmEncrypt::new(&nonce);
    ///
    ///     let data =
    ///         b"Secret data";
    ///
    ///     let (ciphertext, _) =
    ///         encryptor.encrypt_bytes(
    ///             data,
    ///             &key
    ///         )?;
    ///
    ///     println!(
    ///         "Encrypted {} bytes",
    ///         ciphertext.len()
    ///     );
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn generate_key(&self) -> Result<[u8; 32], CryptoError> {
        let mut key = [0u8; 32];

        getrandom::fill(&mut key).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(key)
    }
}
