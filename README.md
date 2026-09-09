# encipher

[![Crates.io](https://img.shields.io/crates/v/encipher)](https://crates.io/crates/encipher)
[![Docs.rs](https://docs.rs/encipher/badge.svg)](https://docs.rs/encipher)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)

A fast, allocation-conscious session-data cipher for Rust.

Every backend is a standard, independently-audited AEAD construction —
this crate's own contribution is not a new algorithm, it's a safe,
ergonomic, low-allocation interface around one: nonce handling, key
formatting, token layout, purpose binding, and expiry all handled for
you, so the only decision left to make is which backend fits your
deployment target.

> **Version 3.0** fixes nonce generation across `fork` and
> improves buffer reuse. Existing 2.x tokens remain compatible with the
> same key and backend. See [Upgrading from 2.x](#upgrading-from-2x) and
> [CHANGELOG.md](CHANGELOG.md) for the API changes and the earlier 0.x migration.

## Installation

```toml
[dependencies]
encipher = "3"
```

## Usage

```rust
use encipher::{Encipher, Backend};

let cipher = Encipher::new(Some(YOUR_RANDOM_KEY), None, Backend::Aes256Gcm).unwrap();

let token   = cipher.encrypt("{\"id\":1,\"username\":\"shaya\"}", None, None).unwrap();
let decoded = cipher.decrypt(&token).unwrap();

assert_eq!(decoded, "{\"id\":1,\"username\":\"shaya\"}");
```

`YOUR_RANDOM_KEY` must be a genuinely random 128-bit value, generated
once with a real CSPRNG and stored like any other secret — see the
[`Encipher::new`](https://docs.rs/encipher) docs for why.

## Choosing a backend

```rust
use encipher::Backend;

Backend::Aes256Gcm;         // fastest on any CPU with AES instruction support
Backend::XChaCha20Poly1305; // fastest without it, and a fine choice anywhere
```

There is no `Auto` option. A single process can safely check its own CPU
at startup and pick for itself, but a *fleet* of them can't — a token
minted under one backend won't decrypt under the other, and a token
never says which one produced it. If your servers don't all share the
same CPU capabilities, pick one backend and set it everywhere; don't let
each machine decide on its own.

## Purpose binding

```rust
// Minting a token for something other than a plain session:
let token = cipher.encrypt(payload, None, Some("password-reset")).unwrap();

// Reading it back requires stating the same purpose explicitly:
let payload = cipher.decrypt_for(&token, "password-reset").unwrap();

// decrypt() only ever accepts the default purpose, "session":
cipher.decrypt(&token); // Err(WrongPurpose) — this token wasn't a session
```

A token minted for one purpose is authenticated data — it can't be
*forged* into another purpose — and `decrypt`/`decrypt_for` won't accept
it under the wrong one either, so a password-reset token can never be
mistaken for a session token even under the same key.

Explicit purposes must contain 1–255 UTF-8 bytes. Empty purposes return
`EmptyPurpose`; longer ones return `PurposeTooLong`.

## Expiry

`expires_at` is an absolute Unix timestamp in seconds. The token is
expired when the current time is greater than or equal to that timestamp.
Pass `None` for no expiry; `Some(0)` returns `InvalidExpiry`. Plaintext is
limited to 16 KiB (`TooLarge` when exceeded).

## Reusing buffers

`encrypt_into` clears and rewrites the supplied `String`.
`encrypt_into_with_scratch` additionally reuses a `Vec<u8>` for ciphertext
and its authentication tag. Both retain their allocations when capacity
is sufficient; the operation still allocates for token context.
Each concurrent call needs its own buffers.

Both methods clear `output` even on error. `scratch` is overwritten on
success and remains unchanged on a returned error.

Nonces are drawn from operating system randomness on every encryption.
If it is unavailable, encryption returns `RandomnessUnavailable`.
Workers can still read each other's tokens with the same key and backend.

## Upgrading from 2.x

- Replace `Some(0)` with `None` when minting non-expiring tokens.
- `EncipherError` adds `InvalidExpiry`, `PurposeTooLong`, and
  `RandomnessUnavailable`. It is now `#[non_exhaustive]`, so exhaustive
  error matches need a wildcard arm (`_`).
- Purposes longer than 255 UTF-8 bytes return `PurposeTooLong` instead of
  `TooLarge`.

The token format and key derivation are unchanged. Existing 2.x tokens
remain readable, including old `Some(0)` tokens, which remain non-expiring.
Tokens from 0.x remain incompatible.

## Using an environment variable

```rust
use encipher::{Encipher, Backend};

// Set ENCIPHER_KEY=<your random 128-bit value> in your environment
let cipher = Encipher::new(None, Some("ENCIPHER_KEY"), Backend::Aes256Gcm).unwrap();
```

## Revocation

There is no `session_id` or similar in this crate. You can store the token
string itself in a revocation list when a caller logs out. Random nonces
make token collisions unlikely; they do not guarantee uniqueness.
Where that list lives (a local cache, Redis, a database) is a deployment
decision this crate deliberately has no opinion on.

## Fuzzing

`decrypt`/`decrypt_for` and the token-context parser are both fuzz-tested
(see `fuzz/`) — run them yourself with:

```sh
cargo +nightly fuzz run decrypt
cargo +nightly fuzz run context_from_bytes
```

## License

Licensed under the [Apache License 2.0](LICENSE).
