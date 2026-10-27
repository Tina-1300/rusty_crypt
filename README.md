# rusty_crypt

![Crates.io Version](https://img.shields.io/crates/v/rusty_crypt?style=plastic)
[![Documentation](https://docs.rs/rusty_crypt/badge.svg)](https://docs.rs/rusty_crypt)
![Crates.io License](https://img.shields.io/crates/l/rusty_crypt?style=plastic)


A simple and secure Rust library providing an easy-to-use interface for **AES-256-GCM-SIV authenticated encryption**.

`rusty_crypt` provides high-level utilities to easily integrate modern symmetric encryption into Rust applications.



## Features

- AES-256-GCM-SIV encryption and decryption
- Secure key generation
- Secure nonce generation
- Binary data support
- Explicit error handling


---

## Quick Start

```rust
use rusty_crypt::{AesGcmEncrypt, AesGcmDecrypt, AesGcmSiv256Key, AesGcmGeneratedNonce};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let key = AesGcmSiv256Key::from_bytes([0u8; AesGcmSiv256Key::SIZE]);
    let nonce_generator = AesGcmGeneratedNonce;

    let encryptor = AesGcmEncrypt::new(&nonce_generator, &key)?;
    let decryptor = AesGcmDecrypt::new(&key)?;

    let data = b"Hello, rusty_crypt!";

    let (ciphertext, nonce) = encryptor.encrypt_bytes(data)?;

    let decrypted = decryptor.decrypt_bytes(&ciphertext, &nonce)?;

    assert_eq!(data, decrypted.as_slice());

    Ok(())
}
```


Security
rusty_crypt uses AES-256-GCM-SIV.

- Key size: 32 bytes (256 bits)
- Nonce size: 12 bytes (96 bits)
- Never reuse a nonce with the same key.
- Keep encryption keys secret.


---

# Documentation

Full API documentation:

https://docs.rs/rusty_crypt

---

# License

MIT License
