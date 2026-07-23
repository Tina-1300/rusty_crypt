use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose};
use std::convert::TryFrom;

use crate::error::CryptoError;

use super::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;

/// AES-256-GCM encryption handler.
///
/// `AesGcmEncrypt` provides encryption functions using the AES-256-GCM
/// authenticated encryption algorithm.
///
/// AES-GCM provides:
///
/// - Confidentiality: encrypted data cannot be read without the key
/// - Integrity: modified ciphertext will fail decryption
/// - Authentication: incorrect keys or corrupted data are rejected
///
/// This structure requires an [`AesGcmGeneratedNonce`] instance to generate
/// secure random nonces for every encryption operation.
///
/// # Key requirements
///
/// AES-256-GCM requires a 256-bit key:
///
/// ```text
/// 32 bytes
/// ```
///
/// Keys can be generated using [`AesGeneratedKey`](crate::AesGeneratedKey).
///
/// # Example
///
/// Encrypt and decrypt a text message:
///
/// ```rust
/// use base64::{Engine, engine::general_purpose};
/// use rusty_crypt::{
///     AesGeneratedKey,
///     AesGcmEncrypt,
///     AesGcmDecrypt,
///     AesGcmGeneratedNonce,
/// };
///
/// fn main() -> Result<(), Box<dyn std::error::Error>> {
///
///     let key = AesGeneratedKey.generate_key()?;
///
///     let key_base64 = general_purpose::STANDARD.encode(key);
///
///     let nonce_generator = AesGcmGeneratedNonce;
///
///     let encryptor = AesGcmEncrypt::new(&nonce_generator);
///
///     let decryptor = AesGcmDecrypt;
///
///     let encrypted = encryptor.encrypt(
///         "Hello rusty_crypt!",
///         &key_base64
///     )?;
///
///     let decrypted = decryptor.decrypt(
///         &encrypted,
///         &key_base64
///     )?;
///
///     assert_eq!(decrypted, "Hello rusty_crypt!");
///
///     Ok(())
/// }
/// ```
pub struct AesGcmEncrypt<'a> {
    nonce_generator: &'a AesGcmGeneratedNonce,
}

impl<'a> AesGcmEncrypt<'a> {
    /// Creates a new AES-GCM encryptor.
    ///
    /// # Arguments
    ///
    /// * `nonce_generator`
    ///     - Secure nonce generator used during encryption
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusty_crypt::{
    ///     AesGcmEncrypt,
    ///     AesGcmGeneratedNonce,
    /// };
    ///
    /// let nonce = AesGcmGeneratedNonce;
    ///
    /// let encryptor = AesGcmEncrypt::new(&nonce);
    /// ```
    pub fn new(nonce_generator: &'a AesGcmGeneratedNonce) -> Self {
        Self { nonce_generator }
    }

    /// Encrypts a UTF-8 string using AES-256-GCM.
    ///
    /// The encryption output format is:
    ///
    /// ```text
    /// BASE64_NONCE::BASE64_CIPHERTEXT
    /// ```
    ///
    /// The generated nonce is automatically included with the ciphertext
    /// to allow decryption later.
    ///
    /// # Arguments
    ///
    /// * `plaintext`
    ///     - Text data to encrypt
    ///
    /// * `base64_key`
    ///     - AES-256 key encoded in Base64
    ///     - The decoded key must contain exactly 32 bytes
    ///
    /// # Returns
    ///
    /// Returns a formatted encrypted string containing:
    ///
    /// - The generated nonce
    /// - The encrypted ciphertext
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    ///
    /// - [`CryptoError::InvalidBase64`]
    ///   when the Base64 key cannot be decoded
    /// - [`CryptoError::InvalidKeySize`]
    ///   when the AES key is not exactly 32 bytes
    /// - [`CryptoError::RandomGenerationFailed`]
    ///   when nonce generation fails
    /// - [`CryptoError::EncryptionFailed`]
    ///   when AES-GCM encryption fails
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use base64::{Engine, engine::general_purpose};
    /// use rusty_crypt::{
    ///     AesGeneratedKey,
    ///     AesGcmEncrypt,
    ///     AesGcmGeneratedNonce,
    /// };
    ///
    /// let key = AesGeneratedKey.generate_key()?;
    ///
    /// let key_base64 =
    ///     general_purpose::STANDARD.encode(key);
    ///
    /// let nonce = AesGcmGeneratedNonce;
    ///
    /// let encryptor =
    ///     AesGcmEncrypt::new(&nonce);
    ///
    /// let encrypted =
    ///     encryptor.encrypt(
    ///         "Secret message",
    ///         &key_base64
    ///     )?;
    ///
    /// println!("{}", encrypted);
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn encrypt(&self, plaintext: &str, base64_key: &str) -> Result<String, CryptoError> {
        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(CryptoError::InvalidBase64)?;

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let key = Key::<Aes256Gcm>::try_from(&key_bytes[..])
            .map_err(|_| CryptoError::InvalidKeySize)?;

        let cipher = Aes256Gcm::new(&key);

        let nonce_bytes = self.nonce_generator.generate_nonce()?;

        let nonce = Nonce::try_from(&nonce_bytes[..])
            .map_err(|_| CryptoError::InvalidNonceSize)?;


        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|_| CryptoError::EncryptionFailed)?;

        let ciphertext_base64 = general_purpose::STANDARD.encode(ciphertext);

        let nonce_base64 = general_purpose::STANDARD.encode(nonce_bytes);

        Ok(format!("{nonce_base64}::{ciphertext_base64}"))
    }

    /// Encrypts binary data using AES-256-GCM.
    ///
    /// This method is designed for:
    ///
    /// - Files
    /// - Images
    /// - Videos
    /// - Serialized data
    /// - Arbitrary bytes
    ///
    /// The returned nonce must be stored together with the ciphertext
    /// because it is required during decryption.
    ///
    /// The recommended storage format is:
    ///
    /// ```text
    /// [12 bytes nonce][ciphertext]
    /// ```
    ///
    /// # Arguments
    ///
    /// * `plaintext`
    ///     - Binary data to encrypt
    ///
    /// * `key_bytes`
    ///     - Raw AES-256 key
    ///     - Must contain exactly 32 bytes
    ///
    /// # Returns
    ///
    /// Returns:
    ///
    /// ```text
    /// (
    ///     encrypted_data,
    ///     nonce
    /// )
    /// ```
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    ///
    /// - [`CryptoError::InvalidKeySize`]
    ///   when the AES key is not exactly 32 bytes
    /// - [`CryptoError::EncryptionFailed`]
    ///   when AES-GCM encryption fails
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusty_crypt::{
    ///     AesGeneratedKey,
    ///     AesGcmEncrypt,
    ///     AesGcmGeneratedNonce,
    /// };
    ///
    /// let key =
    ///     AesGeneratedKey.generate_key()?;
    ///
    /// let nonce =
    ///     AesGcmGeneratedNonce;
    ///
    /// let encryptor =
    ///     AesGcmEncrypt::new(&nonce);
    ///
    /// let data =
    ///     b"binary secret data";
    ///
    /// let (ciphertext, nonce) =
    ///     encryptor.encrypt_bytes(
    ///         data,
    ///         &key
    ///     )?;
    ///
    /// println!(
    ///     "Encrypted {} bytes",
    ///     ciphertext.len()
    /// );
    ///
    /// # Ok::<(), Box<dyn std::error::Error>>(())
    /// ```
    pub fn encrypt_bytes(
        &self,
        plaintext: &[u8],
        key_bytes: &[u8],
    ) -> Result<(Vec<u8>, [u8; 12]), CryptoError> {
        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let key = Key::<Aes256Gcm>::try_from(key_bytes)
            .map_err(|_| CryptoError::InvalidKeySize)?;

        let cipher = Aes256Gcm::new(&key);

        let nonce_bytes = self.nonce_generator.generate_nonce()?;

        let nonce = Nonce::try_from(&nonce_bytes[..])
            .map_err(|_| CryptoError::InvalidNonceSize)?;


        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|_| CryptoError::EncryptionFailed)?;

        Ok((ciphertext, nonce_bytes))
    }
}
