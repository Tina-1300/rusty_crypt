use crate::error::CryptoError;

pub struct AesGcmGeneratedNonce;

impl AesGcmGeneratedNonce {
    pub fn generate_nonce(&self) -> Result<[u8; 12], CryptoError> {
        let mut nonce_bytes = [0u8; 12];

        getrandom::fill(&mut nonce_bytes).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(nonce_bytes)
    }
}
