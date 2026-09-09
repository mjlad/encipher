//! AES-256-GCM: the fast path on any CPU with AES instruction support.
//!
//! GCM needs exactly one thing from its caller to stay safe: never reuse a
//! (key, nonce) pair. We satisfy that the simplest way available — draw a
//! fresh 96-bit nonce from the operating system's CSPRNG on every call.
//! At realistic session-token volumes the birthday bound on a 96-bit space
//! is not a practical concern; if that ever stops being true for a given
//! deployment, `Backend::XChaCha20Poly1305`'s 192-bit nonce removes the
//! question entirely.

use aes_gcm::aead::{Aead, AeadInPlace, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};

use crate::{EncipherError, TAG_LEN};

/// Widens the crate's plain `u128` key into the 256-bit key GCM expects.
/// Hashing here is purely a formatting step, not a strengthening one — the
/// entropy of the result is bounded by the entropy that went in, so the
/// caller's key still needs to be a genuinely random `u128`.
pub fn derive_key(key: u128) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.to_be_bytes());
    hasher.update(b"aes256gcm"); // domain-separates this key from the XChaCha20-Poly1305 one derived from the same u128
    hasher.finalize().into()
}

pub fn build_cipher(key: &[u8; 32]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(key).expect("a 32-byte key always fits AES-256")
}

/// Clears `output`, writes ciphertext and tag into it, and returns the nonce.
pub fn encrypt(
    cipher: &Aes256Gcm,
    plaintext: &[u8],
    aad: &[u8],
    output: &mut Vec<u8>,
) -> Result<[u8; 12], EncipherError> {
    let mut nonce_bytes = [0u8; 12];
    SysRng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| EncipherError::RandomnessUnavailable)?;

    output.clear();
    output.reserve(plaintext.len() + TAG_LEN);
    output.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(Nonce::from_slice(&nonce_bytes), aad, output)
        .expect("bounded plaintext and AAD fit the cipher limits");

    Ok(nonce_bytes)
}

/// Decrypts `ciphertext`, verifying it was produced under exactly this
/// `nonce` and `aad`. Any mismatch — a flipped bit anywhere in the
/// ciphertext, the nonce, or the associated data — surfaces as one
/// undifferentiated failure, by design: which part was wrong is not
/// information a caller needs, and distinguishing the cases would only
/// hand an attacker a more precise probe.
pub fn decrypt(cipher: &Aes256Gcm, nonce: &[u8; 12], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncipherError> {
    cipher
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ciphertext, aad })
        .map_err(|_| EncipherError::TamperedData)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let cipher = build_cipher(&derive_key(42));
        let mut ct = Vec::new();
        let nonce = encrypt(&cipher, b"a session's worth of data", b"context", &mut ct).unwrap();
        let pt = decrypt(&cipher, &nonce, &ct, b"context").unwrap();
        assert_eq!(pt, b"a session's worth of data");
    }

    #[test]
    fn rejects_tampered_aad() {
        let cipher = build_cipher(&derive_key(42));
        let mut ct = Vec::new();
        let nonce = encrypt(&cipher, b"data", b"context-a", &mut ct).unwrap();
        assert!(decrypt(&cipher, &nonce, &ct, b"context-b").is_err());
    }

    #[test]
    fn same_plaintext_different_ciphertext_each_time() {
        let cipher = build_cipher(&derive_key(42));
        let mut ct1 = Vec::new();
        let mut ct2 = Vec::new();
        encrypt(&cipher, b"same message", b"", &mut ct1).unwrap();
        encrypt(&cipher, b"same message", b"", &mut ct2).unwrap();
        assert_ne!(ct1, ct2, "a fresh nonce must change the output even for identical input");
    }

    #[test]
    fn key_differs_from_xchacha_backend_derivation() {
        // The regression this exists to catch: forgetting this backend's
        // own domain-separation tag would leave it deriving the exact
        // same key as `xchacha_backend` for the same `u128` seed — this
        // must never be true, tag present or not.
        let aes_key = derive_key(42);
        let xchacha_key = crate::xchacha_backend::derive_key(42);
        assert_ne!(aes_key, xchacha_key);
    }
}
