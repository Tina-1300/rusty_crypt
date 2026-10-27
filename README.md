# rusty_crypt

![Crates.io Version](https://img.shields.io/crates/v/rusty_crypt?style=plastic)
[![Documentation](https://docs.rs/rusty_crypt/badge.svg)](https://docs.rs/rusty_crypt)
![Crates.io License](https://img.shields.io/crates/l/rusty_crypt?style=plastic)


A simple and secure Rust library providing an easy-to-use interface for **AES-256-GCM-SIV authenticated encryption**.

`rusty_crypt` provides high-level utilities and macros to easily integrate modern symmetric encryption into Rust applications.



## Features

- AES-256-GCM-SIV encryption and decryption
- Secure key and nonce generation
- Convenient utility macros (`aes_key!`, `quick_encrypt!`, `quick_decrypt!`)
- Binary data support
- Explicit error handling


---

## Quick Start (Using Macros)

```rust
use rusty_crypt::{aes_key, quick_encrypt, quick_decrypt, AesGeneratedKey};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Generate a secure random key (or load one using the aes_key! macro)
    let key = AesGeneratedKey.generate_key()?;
    
    // Example loading from Base64:
    // let key = aes_key!("JeAe64TzfRKY0f4Mfx4slwqE3dZwQAXKd7UPZ2JF2q0=")?;

    // 2. Quickly encrypt in a single line
    let (ciphertext, nonce) = quick_encrypt!(key.clone(), b"Hello, rusty_crypt!")?;

    // 3. Decrypt just as easily
    let plaintext = quick_decrypt!(key, &ciphertext, &nonce)?;

    println!("Decrypted: {}", String::from_utf8(plaintext)?);

    Ok(())
}
```

## Security

`rusty_crypt` uses AES-256-GCM-SIV.

- Key size: 32 bytes (256 bits)
- Nonce size: 12 bytes (96 bits)
- Never reuse a nonce with the same key.
- Keep encryption keys secret.

---

## Documentation

Full API documentation:

https://docs.rs/rusty_crypt

---

## License

MIT License
