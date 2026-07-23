use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};

use base64::{Engine as _, engine::general_purpose};

pub struct AesGcmDecrypt;

impl AesGcmDecrypt {
    pub fn decrypt(&self, base64_cipher_text: &str, base64_key: &str) -> String {
        let part: Vec<&str> = base64_cipher_text.split("::").collect();

        let key_bytes = general_purpose::STANDARD
            .decode(base64_key)
            .expect("Invalid Base64 Key");
        let nonce_byte = general_purpose::STANDARD
            .decode(part[0])
            .expect("Invalid Base64 nonce");
        let ciphertext = general_purpose::STANDARD
            .decode(part[1])
            .expect("Invalid Base64 ciphertext");

        let key = Key::<Aes256Gcm>::from_slice(&key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&nonce_byte);

        let decrypted = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .expect("Decryption failed");

        String::from_utf8(decrypted).expect("Invalid UTF-8")
    }

    pub fn decrypt_bytes(&self, cipher_bytes: &[u8], key_bytes: &[u8]) -> Vec<u8> {
        let (nonce_bytes, ciphertext) = cipher_bytes.split_at(12);

        let key = Key::<Aes256Gcm>::from_slice(key_bytes);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce_bytes);

        cipher
            .decrypt(nonce, ciphertext)
            .expect("Decryption failed")
    }
}
