#[cfg(test)]
mod tests {
    use rusty_crypt::aes_gcm_256_generated_nonce::AesGcmGeneratedNonce;


    /*
    #[test]
    fn it_works() {

    }
    */

    #[test]
    fn test_checked_type_generated_nonce_aes_gcm_256() {
        let _nonce = AesGcmGeneratedNonce.generate_nonce();
        assert_eq!(_nonce.len(), 12, "nonce should be 12 bytes long for AES GCM 256");
               
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
