use std::convert::TryFrom;

use crate::error::CryptoError;

/// AES-GCM nonce.
///
/// A nonce is not secret and therefore does not require zeroization.
///
/// For AES-GCM, the recommended nonce size is 96 bits (12 bytes).
/// A nonce MUST NOT be reused with the same key.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct AesGcm256Nonce {
    bytes: [u8; Self::SIZE],
}

impl AesGcm256Nonce {
    /// AES-GCM nonce size in bytes.
    pub const SIZE: usize = 12;

    /// Creates a nonce from exactly 12 bytes.
    #[inline]
    pub const fn from_bytes(bytes: [u8; Self::SIZE]) -> Self {
        Self { bytes }
    }

    /// Creates a nonce from a byte slice.
    ///
    /// Returns `CryptoError::InvalidNonceSize` if the slice
    /// does not contain exactly 12 bytes.
    #[inline]
    pub fn try_from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        let bytes: [u8; Self::SIZE] = bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidNonceSize)?;

        Ok(Self::from_bytes(bytes))
    }

    /// Returns the nonce as a byte array reference.
    #[inline]
    pub(crate) const fn as_bytes(&self) -> &[u8; Self::SIZE] {
        &self.bytes
    }

    /// Returns the nonce size in bytes.
    #[inline]
    pub const fn size(&self) -> usize {
        Self::SIZE
    }

    /// Returns the nonce as a byte slice.
    #[inline]
    pub const fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Consumes the nonce and returns the underlying bytes.
    #[inline]
    pub const fn into_bytes(self) -> [u8; Self::SIZE] {
        self.bytes
    }
}

impl TryFrom<&[u8]> for AesGcm256Nonce {
    type Error = CryptoError;

    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Self::try_from_bytes(bytes)
    }
}

impl From<[u8; AesGcm256Nonce::SIZE]> for AesGcm256Nonce {
    #[inline]
    fn from(bytes: [u8; Self::SIZE]) -> Self {
        Self::from_bytes(bytes)
    }
}

impl AsRef<[u8]> for AesGcm256Nonce {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::fmt::Debug for AesGcm256Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesGcm256Nonce({:02x?})", self.bytes)
    }
}
