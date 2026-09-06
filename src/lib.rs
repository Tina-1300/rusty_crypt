//! AES-256-GCM cryptographic primitives and utilities.
//!
//! This module provides encryption and decryption using AES-256-GCM,
//! along with utilities for generating and managing encryption keys
//! and nonces.
//!
//! The main types are re-exported at the module level for convenient
//! access.
//!
//! # Main Types
//!
//! - [`AesGcm256`] provides high-level AES-256-GCM encryption and decryption.
//! - [`AesGcmEncrypt`] provides encryption operations.
//! - [`AesGcmDecrypt`] provides decryption operations.
//! - [`AesGcm256Key`] represents an AES-256 encryption key.
//! - [`AesGcm256Nonce`] represents an AES-GCM nonce.
//! - [`AesGeneratedKey`] generates cryptographically secure AES-256 keys.
//! - [`AesGcmGeneratedNonce`] generates AES-GCM nonces.
//! - [`CryptoError`] represents errors that can occur during cryptographic operations.
pub mod aes_gcm_256;
pub mod aes_gcm_256_decrypt;
pub mod aes_gcm_256_encrypt;
pub mod aes_gcm_256_generated_key;
pub mod aes_gcm_256_generated_nonce;
pub mod aes_gcm_256_key;
pub mod aes_gcm_256_nonce;
pub mod error;

pub use self::aes_gcm_256::AesGcm256;
pub use self::aes_gcm_256_decrypt::AesGcmDecrypt;
pub use self::aes_gcm_256_encrypt::AesGcmEncrypt;
pub use self::aes_gcm_256_generated_key::AesGeneratedKey;
pub use self::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;
pub use self::aes_gcm_256_key::AesGcm256Key;
pub use self::aes_gcm_256_nonce::AesGcm256Nonce;
pub use self::error::CryptoError;
