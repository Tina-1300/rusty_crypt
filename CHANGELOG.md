# Changelog

## [0.4.0](https://github.com/Tina-1300/rusty_crypt/compare/v0.3.0...v0.4.0) (2026-10-27)


### ✨ Features

* add helper macros and update English documentation ([3ba292c](https://github.com/Tina-1300/rusty_crypt/commit/3ba292cdc01d831dc2b334d1f7691c8ed7f2b59f))


### ♻️ Refactoring

* **cipher:** rename AesGcm256 to AesGcmSiv256 ([bc10182](https://github.com/Tina-1300/rusty_crypt/commit/bc10182304813fa0f0939db90c7c28d9ff9a201d))
* **decrypt:** rename AesGcmDecrypt to AesGcmSivDecrypt ([0baff56](https://github.com/Tina-1300/rusty_crypt/commit/0baff56c53cf8514bcb92a5d034a7f4086f8e2a9))
* **encrypt:** rename AesGcmEncrypt to AesGcmSivEncrypt ([012bbd8](https://github.com/Tina-1300/rusty_crypt/commit/012bbd80af08859c3b8e141f2d5b36682aa73ed7))
* **keys:** rename AesGcm256Key to AesGcmSiv256Key ([3f83eea](https://github.com/Tina-1300/rusty_crypt/commit/3f83eea7da44716450be87559c8c52d9e96029a3))
* **nonces:** rename AesGcm256Nonce to AesGcmSiv256Nonce ([54ef1cb](https://github.com/Tina-1300/rusty_crypt/commit/54ef1cbd193901d08bf91dd29fbeb827c57feff6))
* **nonces:** rename AesGcmGeneratedNonce to AesGcmSivGeneratedNonce ([1f09f13](https://github.com/Tina-1300/rusty_crypt/commit/1f09f131e805ecd890f0dd1d9655adddad0982c2))

## [0.3.0](https://github.com/Tina-1300/rusty_crypt/compare/v0.2.1...v0.3.0) (2026-10-26)


### ✨ Features

* **crypto:** migrate AES-256-GCM tests to use aes-gcm-siv wrapper ([66d04ab](https://github.com/Tina-1300/rusty_crypt/commit/66d04abc243f5780732e6dac9b84a17855c63415))

## [0.2.1](https://github.com/Tina-1300/rusty_crypt/compare/v0.2.0...v0.2.1) (2026-10-26)


### 🐛 Bug Fixes

* update ctutils to resolve vulnerability ([93cd5d6](https://github.com/Tina-1300/rusty_crypt/commit/93cd5d6ec85fd54215e82292ae86d6fb21c26356))

## [0.2.0](https://github.com/Tina-1300/rusty_crypt/compare/v0.1.0...v0.2.0) (2026-09-10)


### ✨ Features

* implement From for AES-GCM-256 keys ([cfdb798](https://github.com/Tina-1300/rusty_crypt/commit/cfdb798f4e76fdc66bce9023ecbdf5405dd8e6f2))
* **key:** implement Clone for AES-GCM-256 keys ([ee58b4d](https://github.com/Tina-1300/rusty_crypt/commit/ee58b4dee8fec83bb0a456d7f4422724feb9d5b7))
* **key:** implement PartialEq and Eq for AES-GCM-256 keys ([3a3334d](https://github.com/Tina-1300/rusty_crypt/commit/3a3334de20a0233f376d6fc00fc9838624826afa))


### 🐛 Bug Fixes

* **key:** format ([73f7c2f](https://github.com/Tina-1300/rusty_crypt/commit/73f7c2fd9877c31fba44e137bdc3c56d54231289))


### ⚡ Performance

* **bench:** add AES-GCM-256 key generation benchmarks ([f1bcbfb](https://github.com/Tina-1300/rusty_crypt/commit/f1bcbfbecc3d93d3b920651255ec3733bfc22e8b))
* **bench:** add AES-GCM-256 nonce generation benchmark ([785f2e5](https://github.com/Tina-1300/rusty_crypt/commit/785f2e5ec2111692a90eda1901955b60181833b4))

## 0.1.0 (2026-09-06)


### ✨ Features

* initial implementation ([3a055f2](https://github.com/Tina-1300/rusty_crypt/commit/3a055f27d2786d21b6fe05f51d18fd55bd264e1e))


### 🐛 Bug Fixes

* **ci:** configure cargo-deny license checks ([3007cf6](https://github.com/Tina-1300/rusty_crypt/commit/3007cf64830faf46d576594c40625af62d81d7ec))
