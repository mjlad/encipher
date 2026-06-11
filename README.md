# encipher

[![Crates.io](https://img.shields.io/crates/v/encipher)](https://crates.io/crates/encipher)
[![Docs.rs](https://docs.rs/encipher/badge.svg)](https://docs.rs/encipher)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A fast session-data cipher for Rust.

Designed specifically for encrypting non-critical session data
such as user IDs and usernames. Uses a keyed substitution cipher
with rotating lookup tables seeded via ChaCha20,
and HMAC-SHA256 for data integrity verification.

> Not intended as a general-purpose cryptographic library.
> Not suitable for sensitive data such as passwords or financial information.

## Installation

```toml
[dependencies]
encipher = "0.1.0"
```

## Usage

```rust
use encipher::Encipher;

let step = 7; // controls the substitution offset (1..=255)
let cipher = Encipher::new(Some(42), None, step).unwrap();

let token   = cipher.encrypt("{\"id\":1,\"username\":\"shaya\"}");
let decoded = cipher.decrypt(&token).unwrap();

assert_eq!(decoded, "{\"id\":1,\"username\":\"shaya\"}");
```

## Using an Environment Variable

```rust
use encipher::Encipher;

// Set APP_KEY=12345 in your environment
let cipher = Encipher::new(None, Some("APP_KEY"), 7).unwrap();
```

## License

Licensed under the [Apache License 2.0](LICENSE).