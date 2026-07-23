use crate::error::CryptoError;

pub struct AesGeneratedKey;

impl AesGeneratedKey {
    pub fn generate_key(&self) -> Result<[u8; 32], CryptoError> {
        let mut key = [0u8; 32];

        getrandom::fill(&mut key).map_err(|_| CryptoError::RandomGenerationFailed)?;

        Ok(key)
    }
}
