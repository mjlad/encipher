//! Fuzzes `Encipher::decrypt`/`decrypt_for` with arbitrary strings — the
//! exact shape of input this method sees in real use: a token string
//! from an untrusted caller, with no guarantee it was ever produced by
//! `encrypt` in the first place. The property under test is simple and
//! absolute: no matter what garbage arrives, this must return an `Err`,
//! never panic.

#![no_main]

use encipher::{Backend, Encipher};
use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;

static CIPHER: OnceLock<Encipher> = OnceLock::new();

fn cipher() -> &'static Encipher {
    CIPHER.get_or_init(|| {
        // A fixed key is fine here — this target is testing parsing and
        // authentication robustness against malformed input, not key
        // secrecy, so reusing one key across the whole fuzzing run (built
        // once, not once per input) keeps each iteration fast.
        Encipher::new(Some(0x1F3E5D7C9B0A2F4E6D8C0B1A3F5E7D9C), None, Backend::Aes256Gcm).unwrap()
    })
}

fuzz_target!(|data: &[u8]| {
    let Ok(token) = std::str::from_utf8(data) else { return };

    let _ = cipher().decrypt(token);
    let _ = cipher().decrypt_for(token, "some-other-purpose");
});
