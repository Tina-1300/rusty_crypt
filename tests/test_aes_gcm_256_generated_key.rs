#[cfg(test)]
mod tests {
    use rusty_crypt::aes_gcm_256_generated_key::AesGeneratedKey;


    #[test]
    fn test_checked_type_generated_key_aes_gcm_256() {
        let _key = AesGeneratedKey.generate_key();
        assert_eq!(_key.len(), 32, "Key should be 32 bytes long for AES GCM 256");
               
    }

}

