# rusty_crypt

![Crates.io Version](https://img.shields.io/crates/v/rusty_crypt?style=plastic)
[![Documentation](https://docs.rs/rusty_crypt/badge.svg)](https://docs.rs/rusty_crypt)
![Crates.io License](https://img.shields.io/crates/l/rusty_crypt?style=plastic)


A simple and secure Rust library providing an easy-to-use interface for **AES-256-GCM authenticated encryption**.

`rusty_crypt` provides high-level utilities to easily integrate modern symmetric encryption into Rust applications.



## Features

- AES-256-GCM encryption and decryption
- Secure key generation
- Secure nonce generation
- Binary data support
- Explicit error handling


---

## Quick Start

```rust
use rusty_crypt::{AesGcm256, AesGcm256Key};

fn main() -> Result<(), Box<dyn std::error::Error>> {

    let key = AesGcm256Key::from_bytes([0u8; AesGcm256Key::SIZE]);

    let cipher = AesGcm256::new(key);

    let data = b"Hello, rusty_crypt!";

    let (ciphertext, nonce) = cipher.encrypt(data)?;

    let decrypted = cipher.decrypt(&ciphertext, &nonce)?;

    assert_eq!(data, decrypted.as_slice());

    Ok(())
}
```


Security
rusty_crypt uses AES-256-GCM.

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
