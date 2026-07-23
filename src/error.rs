use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Invalid base64")]
    InvalidBase64(#[from] base64::DecodeError),

    #[error("Invalid key size")]
    InvalidKeySize,

    #[error("Invalid nonce size")]
    InvalidNonceSize,

    #[error("Encryption failed")]
    EncryptionFailed,

    #[error("Invalid cipher text")]
    InvalidCiphertext,

    #[error("Decryption failed")]
    DecryptionFailed,

    #[error("Invalid UTF-8")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),
}
