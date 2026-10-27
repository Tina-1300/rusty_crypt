//! AES-256-GCM-SIV cryptographic primitives and utilities.
//!
//! This module provides encryption and decryption using AES-256-GCM-SIV,
//! along with utilities for generating and managing encryption keys
//! and nonces.
//!
//! The main types are re-exported at the module level for convenient
//! access.
//!
//! # Main Types
//!
//! - [`AesGcm256`] provides high-level AES-256-GCM-SIV encryption and decryption.
//! - [`AesGcmSivEncrypt`] provides encryption operations.
//! - [`AesGcmSivDecrypt`] provides decryption operations.
//! - [`AesGcmSiv256Key`] represents an AES-256 encryption key.
//! - [`AesGcmSiv256Nonce`] represents an AES-GCM-SIV nonce.
//! - [`AesGeneratedKey`] generates cryptographically secure AES-256 keys.
//! - [`AesGcmSivGeneratedNonce`] generates AES-GCM-SIV nonces.
//! - [`CryptoError`] represents errors that can occur during cryptographic operations.
pub mod aes_gcm_256;
pub mod aes_gcm_256_generated_key;
pub mod aes_gcm_siv_256_decrypt;
pub mod aes_gcm_siv_256_encrypt;
pub mod aes_gcm_siv_256_generated_nonce;
pub mod aes_gcm_siv_256_key;
pub mod aes_gcm_siv_256_nonce;
pub mod error;

pub use self::aes_gcm_256::AesGcm256;
pub use self::aes_gcm_256_generated_key::AesGeneratedKey;
pub use self::aes_gcm_siv_256_decrypt::AesGcmSivDecrypt;
pub use self::aes_gcm_siv_256_encrypt::AesGcmSivEncrypt;
pub use self::aes_gcm_siv_256_generated_nonce::AesGcmSivGeneratedNonce;
pub use self::aes_gcm_siv_256_key::AesGcmSiv256Key;
pub use self::aes_gcm_siv_256_nonce::AesGcmSiv256Nonce;
pub use self::error::CryptoError;
