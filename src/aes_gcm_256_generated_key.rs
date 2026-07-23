//use rand::{TryRngCore};
use rand::RngCore;
use rand::rngs::OsRng;

//use base64::{engine::general_purpose, Engine as _};

pub struct AesGeneratedKey;

impl AesGeneratedKey {
    pub fn generate_key(&self) -> [u8; 32] {
        let mut key: [u8; 32] = [0u8; 32];
        let _ = OsRng.try_fill_bytes(&mut key);
        key
    }
}
