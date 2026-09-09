//! XChaCha20-Poly1305: the portable path, for CPUs without AES instruction
//! support — and a perfectly reasonable default even on ones with it.
//!
//! Where GCM asks its caller to be careful about nonce reuse, XChaCha20's
//! 192-bit nonce makes the question moot: drawing it uniformly at random
//! on every call carries no meaningful collision risk at any volume a
//! session-token system will ever see in practice. One less thing to get
//! right.

use chacha20poly1305::aead::{Aead, AeadInPlace, Payload};
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce};
use rand::{rngs::SysRng, TryRng};
use sha2::{Digest, Sha256};

use crate::{EncipherError, TAG_LEN};

/// Widens the crate's plain `u128` key into the 256-bit key XChaCha20
/// expects. As with the AES-GCM backend, this is formatting, not
/// strengthening — see [`crate::aes_backend::derive_key`].
pub fn derive_key(key: u128) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(key.to_be_bytes());
    hasher.update(b"xchacha20poly1305"); // domain-separates this key from the AES-GCM one derived from the same u128
    hasher.finalize().into()
}

pub fn build_cipher(key: &[u8; 32]) -> XChaCha20Poly1305 {
    XChaCha20Poly1305::new_from_slice(key).expect("a 32-byte key always fits XChaCha20-Poly1305")
}

/// Clears `output`, writes ciphertext and tag into it, and returns the nonce.
pub fn encrypt(
    cipher: &XChaCha20Poly1305,
    plaintext: &[u8],
    aad: &[u8],
    output: &mut Vec<u8>,
) -> Result<[u8; 24], EncipherError> {
    let mut nonce_bytes = [0u8; 24];
    SysRng.try_fill_bytes(&mut nonce_bytes)
        .map_err(|_| EncipherError::RandomnessUnavailable)?;

    output.clear();
    output.reserve(plaintext.len() + TAG_LEN);
    output.extend_from_slice(plaintext);
    cipher
        .encrypt_in_place(XNonce::from_slice(&nonce_bytes), aad, output)
        .expect("bounded plaintext and AAD fit the cipher limits");

    Ok(nonce_bytes)
}

/// Decrypts `ciphertext`, verifying it was produced under exactly this
/// `nonce` and `aad` — see [`crate::aes_backend::decrypt`] for why failures
/// are deliberately undifferentiated.
pub fn decrypt(cipher: &XChaCha20Poly1305, nonce: &[u8; 24], ciphertext: &[u8], aad: &[u8]) -> Result<Vec<u8>, EncipherError> {
    cipher
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ciphertext, aad })
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
    fn key_differs_from_aes_backend_derivation() {
        // Same u128 seed, different derived key — the domain-separation
        // tag above must actually change the output, not just decorate it.
        let aes_key = crate::aes_backend::derive_key(42);
        let xchacha_key = derive_key(42);
        assert_ne!(aes_key, xchacha_key);
    }
}
