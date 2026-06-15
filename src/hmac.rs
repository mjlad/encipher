use base64ct::{Base64UrlUnpadded, Encoding};
use hmac::{Hmac, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;


/// Combines key and start_from into a 16-byte secret.
/// Concatenation is used instead of addition to avoid collisions
/// (different inputs producing the same sum).
/// to_be_bytes ensures consistent byte order across all platforms (Big Endian).
fn build_secret(key: u64, start_from: usize) -> [u8; 16] {
    let mut secret = [0u8; 16];
    secret[..8].copy_from_slice(&key.to_be_bytes());
    secret[8..].copy_from_slice(&(start_from as u64).to_be_bytes());
    secret
}


/// Produces an HMAC-SHA256 signature for the given ciphertext.
pub fn sign(cipher_text: &str, start_from: usize, key: u64) -> String {
    let mut mac = HmacSha256::new_from_slice(
        &build_secret(key, start_from))
        .expect("HMAC init failed");
    mac.update(cipher_text.as_bytes());
    Base64UrlUnpadded::encode_string(&mac.finalize().into_bytes())
}


/// Verifies the signature using constant-time comparison to prevent timing attacks.
/// Uses `base64ct` for constant-time Base64 decoding to prevent side-channel leakage.
pub fn verify(cipher_text: &str, start_from: usize, key: u64, signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(
        &build_secret(key, start_from))
        .expect("HMAC init failed");
    mac.update(cipher_text.as_bytes());

    let mut buf = [0u8; 32];
    let sig_bytes = match Base64UrlUnpadded::decode(signature, &mut buf) {
        Ok(bytes) => bytes,
        Err(_)    => &buf[..],
    };

    mac.verify_slice(&sig_bytes).is_ok()
}
