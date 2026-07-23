use crate::error::CryptoError;

/// Generates secure random nonces for AES-256-GCM encryption.
///
/// An AES-GCM nonce must be unique for every encryption operation
/// performed with the same key. Reusing a nonce with the same key
/// can compromise the security of the encryption.
///
/// This generator creates a cryptographically secure random nonce
/// using the operating system random number generator through
/// `getrandom`.
///
/// # Nonce size
///
/// AES-256-GCM uses a 96-bit nonce (12 bytes), which is the recommended
/// size defined by the AES-GCM specification.
///
/// # Example
///
/// ```rust
/// use rusty_crypt::AesGcmGeneratedNonce;
///
/// let nonce_generator = AesGcmGeneratedNonce;
///
/// let nonce = nonce_generator
///     .generate_nonce()
///     .expect("Nonce generation failed");
///
/// assert_eq!(nonce.len(), 12);
/// ```
pub struct AesGcmGeneratedNonce;

impl AesGcmGeneratedNonce {
    /// Generates a new cryptographically secure AES-256-GCM nonce.
    ///
    /// The generated nonce contains 12 random bytes obtained from the
    /// operating system secure random number generator.
    ///
    /// The nonce is required during AES-GCM encryption and must be stored
    /// alongside the encrypted data to allow later decryption.
    ///
    /// # Returns
    ///
    /// Returns:
    ///
    /// - `Ok([u8; 12])` containing the generated nonce.
    /// - `Err(CryptoError::RandomGenerationFailed)` if secure random
    ///   generation fails.
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusty_crypt::AesGcmGeneratedNonce;
    ///
    /// let generator = AesGcmGeneratedNonce;
    ///
    /// let nonce = generator.generate_nonce()?;
    ///
    /// println!("Generated nonce size: {}", nonce.len());
    ///
    /// # Ok::<(), rusty_crypt::CryptoError>(())
    /// ```
    pub fn generate_nonce(&self) -> Result<[u8; 12], CryptoError> {
        let mut nonce_bytes = [0u8; 12];

        getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(nonce_bytes)
    }
}
