use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
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
    URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}


/// Verifies the signature using constant-time comparison to prevent timing attacks.
pub fn verify(cipher_text: &str, start_from: usize, key: u64, signature: &str) -> bool {
    let mut mac = HmacSha256::new_from_slice(
        &build_secret(key, start_from))
        .expect("HMAC init failed");
    mac.update(cipher_text.as_bytes());

    let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(signature) else {
        return false;
    };

    mac.verify_slice(&sig_bytes).is_ok()
}
