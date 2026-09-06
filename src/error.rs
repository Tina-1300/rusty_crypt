use thiserror::Error;

/// Errors that can occur during cryptographic operations.
#[derive(Debug, Error)]
pub enum CryptoError {
    /// The cipher is invalid or unsupported.
    #[error("Invalid cipher")]
    InvalidCipher,

    /// The input is not valid hexadecimal data.
    #[error("Invalid hex")]
    InvalidHex,

    /// The input is not valid Base64 data.
    #[error("Invalid base64")]
    InvalidBase64(#[from] base64::DecodeError),

    /// The encryption key has an invalid size.
    #[error("Invalid key size")]
    InvalidKeySize,

    /// The nonce has an invalid size.
    #[error("Invalid nonce size")]
    InvalidNonceSize,

    /// Encryption failed.
    #[error("Encryption failed")]
    EncryptionFailed,

    /// The ciphertext is invalid or too short.
    #[error("Invalid cipher text")]
    InvalidCiphertext,

    /// Secure random data generation failed.
    #[error("Random generation failed")]
    RandomGenerationFailed,

    /// Decryption failed, including authentication failure.
    #[error("Decryption failed")]
    DecryptionFailed,

    /// The data is not valid UTF-8.
    #[error("Invalid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}
