//use rand::{TryRngCore};
use rand::RngCore;
use rand::rngs::OsRng;


pub struct AesGcmGeneratedNonce;


impl AesGcmGeneratedNonce {

    
    pub fn generate_nonce(&self) -> [u8; 12] {

        let mut nonce_bytes = [0u8; 12];

        let mut rng = OsRng;

        let _ = rng.try_fill_bytes(&mut nonce_bytes);

        nonce_bytes
    }

}
