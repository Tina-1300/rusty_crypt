use base64::{engine::general_purpose, Engine as _};
use zeroize::Zeroizing;

use crate::error::CryptoError;

/// Secure AES-256-GCM key container.
///
/// Stores exactly 32 bytes (256 bits).
///
/// The internal key material is automatically zeroized
/// when the structure is dropped.
pub struct AesGcm256Key {
    bytes: Zeroizing<[u8; 32]>,
}

impl AesGcm256Key {

    /// Creates a new AES-256 key from raw bytes.
    ///
    /// The provided bytes must contain exactly 32 bytes.
    pub(crate) fn new(bytes: [u8; 32]) -> Self {
        Self {
            bytes: Zeroizing::new(bytes),
        }
    }


    /// Returns the raw AES key bytes.
    ///
    /// This method is restricted to crate usage
    /// to avoid exposing the secret key.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.bytes[..]
    }


    /// Encodes the AES-256 key into Base64.
    ///
    /// Intended for:
    ///
    /// - configuration files
    /// - environment variables
    /// - key storage
    /// - key transport
    ///
    /// The internal AES key remains protected.
    pub fn to_base64(&self) -> String {
        general_purpose::STANDARD.encode(&self.bytes[..])
    }


    /// Creates an AES-256 key from Base64.
    ///
    /// The decoded temporary buffer is automatically
    /// zeroized after use.
    ///
    /// The decoded value must contain exactly:
    ///
    /// ```text
    /// 32 bytes
    /// ```
    pub fn from_base64(
        value: &str,
    ) -> Result<Self, CryptoError> {

        let decoded = Zeroizing::new(
            general_purpose::STANDARD
                .decode(value)
                .map_err(CryptoError::InvalidBase64)?
        );


        let bytes: [u8; 32] =
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| CryptoError::InvalidKeySize)?;


        Ok(Self::new(bytes))
    }


    /// Returns the size of the AES key.
    ///
    /// Always returns:
    ///
    /// ```text
    /// 32 bytes
    /// ```
    pub const fn size() -> usize {
        32
    }
}


impl std::fmt::Debug for AesGcm256Key {

    fn fmt(
        &self,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {

        write!(f, "AesGcm256Key([REDACTED])")
    }
}
