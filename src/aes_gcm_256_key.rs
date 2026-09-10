use aes_gcm::{Aes256Gcm, Key};
use base64::Engine as _;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// AES-256 key.
///
/// The key material is stored inside [`Zeroizing`] so that it is
/// securely cleared from memory when the key is dropped.
pub struct AesGcm256Key {
    bytes: Zeroizing<[u8; Self::SIZE]>,
}

impl AesGcm256Key {
    /// AES-256 key size in bytes.
    pub const SIZE: usize = 32;

    /// Creates an AES-256 key from exactly 32 bytes.
    #[inline]
    pub fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }

    /// Creates an AES-256 key from already zeroizing memory.
    pub(crate) fn from_zeroizing(bytes: Zeroizing<[u8; Self::SIZE]>) -> Self {
        Self { bytes }
    }

    /// Creates an AES-256 key from a byte slice.
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; Self::SIZE] = bytes.try_into().map_err(|_| CryptoError::InvalidKeySize)?;

        Ok(Self::from_bytes(bytes))
    }

    /// Creates an AES-256 key from a Base64-encoded string.
    pub fn from_base64(value: &str) -> Result<Self, CryptoError> {
        let decoded = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .decode(value)
                .map_err(CryptoError::InvalidBase64)?,
        );

        Self::try_from_bytes(&decoded)
    }

    /// Compares two keys using a constant-time comparison.
    #[inline]
    pub fn is_equal(&self, other: &Self) -> bool {
        self.bytes.as_ref().ct_eq(other.bytes.as_ref()).into()
    }

    /// Returns the raw key bytes.
    ///
    /// This method is restricted to the crate.
    #[inline]
    pub(crate) fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Returns the AES-GCM key used to initialize `Aes256Gcm`.
    ///
    /// This conversion does not copy the key material.
    #[allow(clippy::unnecessary_fallible_conversions)]
    #[inline]
    pub(crate) fn as_key(&self) -> &Key<Aes256Gcm> {
        // `AesGcm256Key` is guaranteed to contain exactly 32 bytes,
        // which is exactly the size required by AES-256.
        self.as_bytes()
            .try_into()
            .expect("AesGcm256Key must contain exactly 32 bytes")
    }

    /// Returns the AES-256 key size in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        Self::SIZE
    }
}

impl TryFrom<&[u8]> for AesGcm256Key {
    type Error = CryptoError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl TryFrom<&str> for AesGcm256Key {
    type Error = CryptoError;

    #[inline]
    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::from_base64(value)
    }
}

impl PartialEq for AesGcm256Key {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.bytes.as_ref().ct_eq(other.bytes.as_ref()).into()
    }
}

impl Eq for AesGcm256Key {}

impl Clone for AesGcm256Key {
    #[inline]
    fn clone(&self) -> Self {
        Self::from_bytes(*self.bytes)
    }
}

impl std::fmt::Debug for AesGcm256Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AesGcm256Key")
            .field("bytes", &"[REDACTED]")
            .finish()
    }
}
