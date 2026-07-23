//! # rusty_crypt
//!
//! `rusty_crypt` is a Rust cryptography library providing a simple and safe
//! interface for AES-256-GCM symmetric encryption and decryption.
//!
//! The library focuses on:
//!
//! - AES-256-GCM authenticated encryption
//! - Secure random AES key generation
//! - Secure random nonce generation
//! - Error handling with `Result<T, CryptoError>`
//! - Support for text and binary data encryption
//!
//! ## Features
//!
//! ### AES-256-GCM encryption
//!
//! The library uses AES-256-GCM, which provides:
//!
//! - Confidentiality: encrypted data cannot be read without the key
//! - Integrity: modified ciphertext is detected during decryption
//! - Authentication: invalid keys or corrupted data cause an error
//!
//! ### Secure key generation
//!
//! AES keys are generated using the operating system secure random number
//! generator through the `getrandom` crate.
//!
//! AES-256 requires a 32-byte key.
//!
//! ### Secure nonce generation
//!
//! AES-GCM requires a unique nonce for every encryption operation.
//!
//! This library generates secure 12-byte nonces automatically.
//!
//! ## Basic example
//!
//! ```rust
//! use base64::{engine::general_purpose, Engine};
//!
//! use rusty_crypt::{
//!     AesGeneratedKey,
//!     AesGcmGeneratedNonce,
//!     AesGcmEncrypt,
//!     AesGcmDecrypt,
//! };
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!
//!     let key = AesGeneratedKey.generate_key()?;
//!
//!     let key_base64 = general_purpose::STANDARD.encode(key);
//!
//!     let nonce_generator = AesGcmGeneratedNonce;
//!
//!     let encryptor = AesGcmEncrypt::new(&nonce_generator);
//!
//!     let decryptor = AesGcmDecrypt;
//!
//!     let message = "Hello rusty_crypt";
//!
//!     let encrypted = encryptor.encrypt(
//!         message,
//!         &key_base64,
//!     )?;
//!
//!     let decrypted = decryptor.decrypt(
//!         &encrypted,
//!         &key_base64,
//!     )?;
//!
//!     assert_eq!(message, decrypted);
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Binary data encryption
//!
//! `rusty_crypt` also supports encryption of arbitrary binary data such as:
//!
//! - Files
//! - Images
//! - Documents
//! - Network payloads
//!
//! Use:
//!
//! - [`AesGcmEncrypt::encrypt_bytes`] for encryption
//! - [`AesGcmDecrypt::decrypt_bytes`] for decryption
//!
//! ## Error handling
//!
//! All cryptographic operations return a [`CryptoError`] instead of
//! panicking.
//!
//! This allows applications to properly handle:
//!
//! - Invalid keys
//! - Invalid Base64 data
//! - Encryption failures
//! - Decryption failures
//! - Random generation failures
//!
//! ## Security notes
//!
//! - Never reuse an AES-GCM nonce with the same key.
//! - Never expose AES keys publicly.
//! - Store generated keys securely.
//! - Use a strong key management strategy for production applications.
//!
//! This library provides low-level cryptographic building blocks.
//! Applications requiring password-based encryption, key exchange,
//! or public-key cryptography should implement additional layers.

pub mod aes_gcm_256_decrypt;
pub mod aes_gcm_256_encrypt;
pub mod aes_gcm_256_generated_key;
pub mod aes_gcm_256_generated_nonce;
pub mod error;

pub use self::aes_gcm_256_decrypt::AesGcmDecrypt;
pub use self::aes_gcm_256_encrypt::AesGcmEncrypt;
pub use self::aes_gcm_256_generated_key::AesGeneratedKey;
pub use self::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;
pub use self::error::CryptoError;
