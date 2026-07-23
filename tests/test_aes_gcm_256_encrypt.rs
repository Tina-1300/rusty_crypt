#[cfg(test)]
mod tests {
    use base64::{Engine as _, engine::general_purpose};
    use rusty_crypt::aes_gcm_256_encrypt::AesGcmEncrypt;
    use rusty_crypt::aes_gcm_256_generated_key::AesGeneratedKey;
    use rusty_crypt::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;

    #[test]
    fn test_checked_good_encryption() {
        let message = "ceci est un test vous ne pourrez pas me retrouvez";

        let key = AesGeneratedKey.generate_key();

        let nonce = AesGcmGeneratedNonce;

        let encrypt_aes = AesGcmEncrypt::new(&nonce);

        let key_b64 = general_purpose::STANDARD.encode(key);

        let message_cipher = encrypt_aes
            .encrypt(message, &key_b64)
            .expect("Encryption should succeed");

        assert_ne!(message, message_cipher);
    }

    #[test]
    fn test_checked_good_encryption_full_bytes_version() {
        let key = AesGeneratedKey.generate_key();

        let nonce_gen = AesGcmGeneratedNonce;

        let encryptor = AesGcmEncrypt::new(&nonce_gen);

        let message = b"Hello AES-256-GCM in bytes!";

        let (ciphertext, nonce) = encryptor
            .encrypt_bytes(message, &key)
            .expect("Encryption should succeed");

        let mut full_cipher = Vec::new();

        full_cipher.extend_from_slice(&nonce);

        full_cipher.extend_from_slice(&ciphertext);

        assert!(full_cipher.len() > 12);
    }
}

/*
    // =========   Version 1 ==========

    let txt_message = "I am Tina";

    let key = AesGeneratedKey.generate_key_base64();

    let nonce = AesGcmGeneratedNonce;

    let aes_encryptor = AesGcmEncrypt::new(&nonce);

    let txt_chiffre = aes_encryptor.encrypt(&txt_message, &KEY_ENC_DATA_BS64);

    let txt_decrypt = AesGcmDecrypt.decrypt(&txt_chiffre, &KEY_ENC_DATA_BS64);

    println!("txt : {:#}", txt_message);
    println!("key : {:#}", key);
    println!("txt encrypt : {:#}", txt_chiffre);
    //println!("Nonce : {:#}", nonce_base64);
    println!("txt decrypt : {:#}", txt_decrypt);

    // ======================================================

*/

/*
use rusty_crypt::{
    AesGeneratedKey, AesGcmGeneratedNonce,
    AesGcmEncrypt, AesGcmDecrypt,
};

fn main() {
    let key_gen = AesGeneratedKey;
    let key = key_gen.generate_key();

    let nonce_gen = AesGcmGeneratedNonce;
    let encryptor = AesGcmEncrypt::new(&nonce_gen);
    let decryptor = AesGcmDecrypt;

    let message = b"Hello AES-256-GCM in bytes!";

    // Encrypt
    let (ciphertext, nonce) = encryptor.encrypt_bytes(message, &key);

    // Concat nonce + ciphertext pour transmettre
    let mut full_cipher = Vec::new();
    full_cipher.extend_from_slice(&nonce);
    full_cipher.extend_from_slice(&ciphertext);

    // Decrypt
    let decrypted = decryptor.decrypt_bytes(&full_cipher, &key);

    assert_eq!(decrypted, message);
    println!("Decrypted message: {:?}", String::from_utf8(decrypted).unwrap());
}


*/
