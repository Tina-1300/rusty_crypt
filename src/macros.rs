/// Macro to easily initialize an `AesGcmSiv256Key` from an array or a Base64 string.
///
/// # Example
/// ```rust
/// use rusty_crypt::aes_key;
///
/// let base64_string = "JeAe64TzfRKY0f4Mfx4slwqE3dZwQAXKd7UPZ2JF2q0=";
/// let key = aes_key!(base64_string).unwrap();
/// ```
#[macro_export]
macro_rules! aes_key {
    ($bytes:expr) => {
        $crate::AesGcmSiv256Key::try_from($bytes)
    };
}

/// Quickly encrypts a message with a key and plaintext in a single line.
///
/// # Example
/// ```rust
/// use rusty_crypt::{quick_encrypt, AesGeneratedKey};
///
/// let key = AesGeneratedKey.generate_key().unwrap();
/// let (ciphertext, nonce) = quick_encrypt!(key, b"My secret").unwrap();
/// ```
#[macro_export]
macro_rules! quick_encrypt {
    ($key:expr, $plaintext:expr) => {{
        let cipher = $crate::AesGcmSiv256::new($key);
        cipher.encrypt($plaintext)
    }};
}

/// Quickly decrypts a message with a key, ciphertext, and a nonce.
///
/// # Example
/// ```rust
/// use rusty_crypt::{quick_encrypt, quick_decrypt, AesGeneratedKey};
///
/// let key = AesGeneratedKey.generate_key().unwrap();
/// let (ciphertext, nonce) = quick_encrypt!(key.clone(), b"My secret").unwrap();
/// let plaintext = quick_decrypt!(key, &ciphertext, &nonce).unwrap();
///
/// assert_eq!(plaintext, b"My secret");
/// ```
#[macro_export]
macro_rules! quick_decrypt {
    ($key:expr, $ciphertext:expr, $nonce:expr) => {{
        let cipher = $crate::AesGcmSiv256::new($key);
        cipher.decrypt($ciphertext, $nonce)
    }};
}
