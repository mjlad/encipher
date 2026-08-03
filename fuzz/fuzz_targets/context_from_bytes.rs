//! Fuzzes `aad::Context::from_bytes` directly with arbitrary bytes,
//! bypassing base64 and the token's outer `nonce.context.ciphertext`
//! shell entirely. `decrypt` only ever calls this on bytes that already
//! passed AEAD authentication — but this parser has no way to know that
//! from inside itself, so it must be just as robust on its own as
//! `decrypt` is as a whole. Only reachable with the crate's `fuzzing`
//! feature enabled (see `fuzz/Cargo.toml`), which is what makes this
//! normally-private module `pub` in the first place.

#![no_main]

use encipher::aad::Context;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Context::from_bytes(data);
});
