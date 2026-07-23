# rusty_crypt

[![Crates.io](https://img.shields.io/crates/v/rusty_crypt.svg?cacheSeconds=1)](https://crates.io/crates/rusty_crypt)
[![Documentation](https://docs.rs/rusty_crypt/badge.svg)](https://docs.rs/rusty_crypt)
[![License](https://img.shields.io/crates/l/rusty_crypt.svg)](https://github.com/)

A simple and secure Rust library providing an easy-to-use interface for **AES-256-GCM authenticated encryption**.

`rusty_crypt` provides high-level utilities to easily integrate modern symmetric encryption into Rust applications.

## Features

- 🔐 AES-256-GCM authenticated encryption
- 🔑 Secure AES-256 key generation
- 🎲 Secure nonce generation
- 📦 Text encryption and decryption
- 📁 Binary data encryption and decryption
- ⚠️ Safe error handling with `Result<T, CryptoError>`
- 🚫 No panic-based cryptographic failures

---

# Installation

Add `rusty_crypt` to your `Cargo.toml`:

```toml
[dependencies]
rusty_crypt = "0.4.0"
```

---

# Overview

`rusty_crypt` uses the **AES-256-GCM** algorithm.

AES-GCM provides:

- **Confidentiality**  
  Data is encrypted and cannot be read without the key.

- **Integrity**  
  Any modification of encrypted data is detected.

- **Authentication**  
  Invalid keys or corrupted ciphertext are rejected during decryption.

AES-256 requires a:

```
32 bytes key (256 bits)
```

AES-GCM uses a:

```
12 bytes nonce (96 bits)
```

A unique nonce must be generated for every encryption operation.

---

# Quick Start

## Encrypt and decrypt text

```rust
use base64::{engine::general_purpose, Engine};

use rusty_crypt::{
    AesGeneratedKey,
    AesGcmEncrypt,
    AesGcmDecrypt,
    AesGcmGeneratedNonce,
};


fn main() -> Result<(), Box<dyn std::error::Error>> {

    let key = AesGeneratedKey.generate_key()?;

    let key_base64 = general_purpose::STANDARD.encode(key);


    let nonce_generator = AesGcmGeneratedNonce;


    let encryptor = AesGcmEncrypt::new(
        &nonce_generator
    );


    let decryptor = AesGcmDecrypt;


    let message = "Hello rusty_crypt!";


    let encrypted = encryptor.encrypt(
        message,
        &key_base64
    )?;


    println!(
        "Encrypted: {}",
        encrypted
    );


    let decrypted = decryptor.decrypt(
        &encrypted,
        &key_base64
    )?;


    println!(
        "Decrypted: {}",
        decrypted
    );


    Ok(())
}
```

---

# Encrypt binary data

`rusty_crypt` can encrypt any binary data:

- Files
- Images
- Documents
- Network payloads
- Serialized data


Example:

```rust
use rusty_crypt::{
    AesGeneratedKey,
    AesGcmEncrypt,
    AesGcmDecrypt,
    AesGcmGeneratedNonce,
};


fn main() -> Result<(), Box<dyn std::error::Error>> {

    let key = AesGeneratedKey.generate_key()?;


    let nonce_generator = AesGcmGeneratedNonce;


    let encryptor = AesGcmEncrypt::new(
        &nonce_generator
    );


    let decryptor = AesGcmDecrypt;


    let data = b"Secret binary data";


    let (ciphertext, nonce) =
        encryptor.encrypt_bytes(
            data,
            &key
        )?;


    let mut encrypted_data = Vec::new();


    encrypted_data.extend_from_slice(
        &nonce
    );


    encrypted_data.extend_from_slice(
        &ciphertext
    );


    let decrypted =
        decryptor.decrypt_bytes(
            &encrypted_data,
            &key
        )?;


    assert_eq!(
        data,
        decrypted.as_slice()
    );


    Ok(())
}
```

---

# Key generation

Generate a secure AES-256 key:

```rust
use rusty_crypt::AesGeneratedKey;


fn main() -> Result<(), Box<dyn std::error::Error>> {

    let key = AesGeneratedKey.generate_key()?;


    println!(
        "Key size: {} bytes",
        key.len()
    );


    Ok(())
}
```

Output:

```
Key size: 32 bytes
```

---

# Nonce generation

Generate a secure AES-GCM nonce:

```rust
use rusty_crypt::AesGcmGeneratedNonce;


fn main() -> Result<(), Box<dyn std::error::Error>> {

    let nonce_generator = AesGcmGeneratedNonce;


    let nonce =
        nonce_generator.generate_nonce()?;


    println!(
        "Nonce size: {} bytes",
        nonce.len()
    );


    Ok(())
}
```

Output:

```
Nonce size: 12 bytes
```

---

# Error handling

All cryptographic operations return:

```rust
Result<T, CryptoError>
```

The library does not panic when an encryption or decryption error occurs.

Available errors:

- Invalid Base64
- Invalid AES key size
- Invalid nonce size
- Invalid ciphertext format
- Encryption failure
- Decryption failure
- Invalid UTF-8 data
- Random generation failure


Example:

```rust
use rusty_crypt::AesGcmDecrypt;


fn main() {

    let decryptor = AesGcmDecrypt;


    match decryptor.decrypt(
        "invalid_data",
        "invalid_key"
    ) {

        Ok(value) => {
            println!(
                "Decrypted: {}",
                value
            );
        }


        Err(error) => {
            println!(
                "Crypto error: {}",
                error
            );
        }
    }
}
```

---

# Security recommendations

For secure applications:

- Never reuse an AES-GCM nonce with the same key.
- Never expose encryption keys.
- Store keys securely.
- Do not hardcode keys inside your source code.
- Use a secure key management system for production.

`rusty_crypt` provides low-level cryptographic primitives.


---

# Documentation

Full API documentation:

https://docs.rs/rusty_crypt

---

# License

MIT License
