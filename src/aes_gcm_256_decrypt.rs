use crate::error::CryptoError;
use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use base64::{Engine as _, engine::general_purpose};
use std::convert::TryFrom;

/// AES-256-GCM decryptor.
///
/// This structure provides methods to decrypt data previously encrypted
/// using [`AesGcmEncrypt`](crate::AesGcmEncrypt).
///
/// The implementation uses:
/// - AES-256-GCM for authenticated encryption
/// - Base64 encoding for portable string representation
/// - 256-bit symmetric keys (32 bytes)
/// - 96-bit nonces (12 bytes)
///
/// # Security
///
/// AES-GCM provides both:
/// - Confidentiality (data cannot be read without the key)
/// - Integrity authentication (tampered ciphertext will fail decryption)
///
/// The key must be exactly 32 bytes long.
///
/// # Example
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
///         "Secret message",
///         &key_base64
///     )?;
///
///     let decrypted = decryptor.decrypt(
///         &encrypted,
///         &key_base64
///     )?;
///
///     assert_eq!(decrypted, "Secret message");
///
///     Ok(())
/// }
/// ```
pub struct AesGcmDecrypt;

impl AesGcmDecrypt {
    /// Decrypts a Base64 encoded AES-256-GCM ciphertext.
    ///
    /// This method expects ciphertext formatted as:
    ///
    /// ```text
    /// BASE64_NONCE::BASE64_CIPHERTEXT
    /// ```
    ///
    /// The nonce is extracted automatically from the encrypted data.
    ///
    /// # Arguments
    ///
    /// * `base64_cipher_text`
    ///     - Encrypted data returned by [`AesGcmEncrypt::encrypt`](crate::AesGcmEncrypt::encrypt)
    ///     - Format:
    ///       `nonce::ciphertext`
    ///
    /// * `base64_key`
    ///     - AES-256 encryption key encoded in Base64
    ///     - Must decode to exactly 32 bytes
    ///
    /// # Returns
    ///
    /// Returns the decrypted UTF-8 string on success.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    ///
    /// - [`CryptoError::InvalidCiphertext`]
    ///   if the ciphertext format is invalid
    /// - [`CryptoError::InvalidBase64`]
    ///   if Base64 decoding fails
    /// - [`CryptoError::InvalidKeySize`]
    ///   if the AES key is not 32 bytes
    /// - [`CryptoError::InvalidNonceSize`]
    ///   if the nonce size is invalid
    /// - [`CryptoError::DecryptionFailed`]
    ///   if authentication fails or the key is incorrect
    /// - [`CryptoError::InvalidUtf8`]
    ///   if decrypted bytes are not valid UTF-8
    ///
    pub fn decrypt(
        &self,
        base64_cipher_text: &str,
        base64_key: &str,
    ) -> Result<String, CryptoError> {
        let parts: Vec<&str> = base64_cipher_text.split("::").collect();

        if parts.len() != 2 {
            return Err(CryptoError::InvalidCiphertext);
        }

        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .map_err(CryptoError::InvalidBase64)?;

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let nonce_bytes = general_purpose::STANDARD
            .decode(parts[0])
            .map_err(CryptoError::InvalidBase64)?;

        if nonce_bytes.len() != 12 {
            return Err(CryptoError::InvalidNonceSize);
        }

        let ciphertext = general_purpose::STANDARD
            .decode(parts[1])
            .map_err(CryptoError::InvalidBase64)?;

        let key =
            Key::<Aes256Gcm>::try_from(&key_bytes[..]).map_err(|_| CryptoError::InvalidKeySize)?;
        //let key = Key::<Aes256Gcm>::from_slice(&key_bytes);

        let cipher = Aes256Gcm::new(&key);

        let nonce = Nonce::try_from(&nonce_bytes[..]).map_err(|_| CryptoError::InvalidNonceSize)?;

        let decrypted = cipher
            .decrypt(&nonce, ciphertext.as_ref())
            .map_err(|_| CryptoError::DecryptionFailed)?;

        let text = String::from_utf8(decrypted).map_err(CryptoError::InvalidUtf8)?;

        Ok(text)
    }

    /// Decrypts raw binary AES-256-GCM encrypted data.
    ///
    /// This method is designed for files and binary data.
    ///
    /// The expected input format is:
    ///
    /// ```text
    /// [12 bytes nonce][ciphertext]
    /// ```
    ///
    /// The nonce must be stored before the ciphertext during encryption.
    ///
    /// # Arguments
    ///
    /// * `cipher_bytes`
    ///     - Encrypted data containing nonce + ciphertext
    ///
    /// * `key_bytes`
    ///     - Raw AES-256 key
    ///     - Must be exactly 32 bytes
    ///
    /// # Returns
    ///
    /// Returns the original decrypted bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError`] if:
    ///
    /// - [`CryptoError::InvalidCiphertext`]
    ///   when the encrypted data is smaller than the nonce size
    /// - [`CryptoError::InvalidKeySize`]
    ///   when the AES key is not exactly 32 bytes
    /// - [`CryptoError::DecryptionFailed`]
    ///   when authentication fails or the key is incorrect
    ///
    ///
    /// # Example
    ///
    /// ```rust
    /// use rusty_crypt::{
    ///     AesGcmEncrypt,
    ///     AesGcmDecrypt,
    ///     AesGcmGeneratedNonce,
    ///     AesGeneratedKey,
    /// };
    ///
    /// fn main() -> Result<(), Box<dyn std::error::Error>> {
    ///
    ///     let key = AesGeneratedKey.generate_key()?;
    ///
    ///     let nonce = AesGcmGeneratedNonce;
    ///
    ///     let encryptor = AesGcmEncrypt::new(&nonce);
    ///
    ///     let decryptor = AesGcmDecrypt;
    ///
    ///     let data = b"binary secret data";
    ///
    ///     let (ciphertext, nonce) =
    ///         encryptor.encrypt_bytes(data, &key)?;
    ///
    ///     let mut encrypted = Vec::new();
    ///
    ///     encrypted.extend_from_slice(&nonce);
    ///     encrypted.extend_from_slice(&ciphertext);
    ///
    ///     let decrypted =
    ///         decryptor.decrypt_bytes(&encrypted, &key)?;
    ///
    ///     assert_eq!(decrypted, data);
    ///
    ///     Ok(())
    /// }
    /// ```
    pub fn decrypt_bytes(
        &self,
        cipher_bytes: &[u8],
        key_bytes: &[u8],
    ) -> Result<Vec<u8>, CryptoError> {
        if cipher_bytes.len() < 12 {
            return Err(CryptoError::InvalidCiphertext);
        }

        if key_bytes.len() != 32 {
            return Err(CryptoError::InvalidKeySize);
        }

        let (nonce_bytes, ciphertext) = cipher_bytes.split_at(12);

        let key = Key::<Aes256Gcm>::try_from(key_bytes).map_err(|_| CryptoError::InvalidKeySize)?;

        let cipher = Aes256Gcm::new(&key);

        let nonce = Nonce::try_from(nonce_bytes).map_err(|_| CryptoError::InvalidNonceSize)?;

        cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|_| CryptoError::DecryptionFailed)
    }
}
