use thiserror::Error;

/// Errors returned by `rusty_crypt`.
///
/// This enum represents all possible failures that can occur during:
///
/// - AES-256-GCM encryption
/// - AES-256-GCM decryption
/// - Base64 encoding/decoding
/// - Key validation
/// - Nonce validation
/// - Secure random generation
///
/// Every public function in this crate returns a [`Result`] containing
/// either the expected value or a [`CryptoError`].
///
/// # Example
///
/// ```rust
/// use rusty_crypt::{AesGcmDecrypt, CryptoError};
///
/// fn decrypt_data() -> Result<String, CryptoError> {
///     let decryptor = AesGcmDecrypt;
///
///     let decrypted = decryptor.decrypt(
///         "invalid_ciphertext",
///         "invalid_key",
///     )?;
///
///     Ok(decrypted)
/// }
/// ```
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The provided Base64 data is invalid.
    ///
    /// This error can happen when:
    ///
    /// - The encryption key is not valid Base64
    /// - The ciphertext is not valid Base64
    /// - The nonce is not valid Base64
    #[error("Invalid base64")]
    InvalidBase64(#[from] base64::DecodeError),

    /// The AES key size is invalid.
    ///
    /// AES-256-GCM requires exactly:
    ///
    /// ```text
    /// 32 bytes (256 bits)
    /// ```
    ///
    /// Any other key size will be rejected.
    #[error("Invalid key size")]
    InvalidKeySize,

    /// The AES-GCM nonce size is invalid.
    ///
    /// AES-256-GCM requires a nonce of:
    ///
    /// ```text
    /// 12 bytes (96 bits)
    /// ```
    #[error("Invalid nonce size")]
    InvalidNonceSize,

    /// Encryption operation failed.
    ///
    /// This error is returned when AES-GCM cannot encrypt the provided data.
    #[error("Encryption failed")]
    EncryptionFailed,

    /// The ciphertext format is invalid.
    ///
    /// This can happen when:
    ///
    /// - The encrypted data format is incorrect
    /// - The nonce is missing
    /// - The ciphertext structure is corrupted
    #[error("Invalid cipher text")]
    InvalidCiphertext,

    /// Secure random generation failed.
    ///
    /// This error can occur when generating:
    ///
    /// - AES encryption keys
    /// - AES-GCM nonces
    #[error("Random generation failed")]
    RandomGenerationFailed,

    /// Decryption operation failed.
    ///
    /// This error is returned when:
    ///
    /// - The encryption key is incorrect
    /// - The ciphertext was modified
    /// - Authentication verification failed
    #[error("Decryption failed")]
    DecryptionFailed,

    /// The decrypted bytes are not valid UTF-8.
    ///
    /// This error only occurs when decrypting text data.
    ///
    /// Use byte decryption methods such as:
    ///
    /// [`AesGcmDecrypt::decrypt_bytes`](crate::AesGcmDecrypt::decrypt_bytes)
    ///
    /// when working with arbitrary binary data.
    #[error("Invalid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}
