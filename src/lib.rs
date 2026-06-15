//! A fast session-data cipher for Rust.
//!
//! Designed specifically for encrypting non-critical session data
//! such as user IDs and usernames. Uses a keyed substitution cipher
//! with rotating lookup tables seeded via ChaCha20,
//! and HMAC-SHA256 for data integrity verification.
//!
//! Not intended as a general-purpose cryptographic library.
//! Not suitable for sensitive data such as passwords or financial information.
//! 
//! # Example
//!
//! ```rust
//! use encipher::Encipher;
//!
//! let step = 7; // controls the substitution offset (1..=255)
//! let cipher = Encipher::new(Some(42), None, step).unwrap();
//!
//! let token   = cipher.encrypt("{\"id\":1,\"username\":\"shaya\"}");
//! let decoded = cipher.decrypt(&token).unwrap();
//!
//! assert_eq!(decoded, "{\"id\":1,\"username\":\"shaya\"}");
//! ```

mod cipher;
mod hmac;
mod lists;

use thiserror::Error;
use base64ct::{Base64Url, Encoding};
use rand::RngExt;

use lists::{CipherList, generate_lists};


const NUM_LISTS: usize = 100;


#[derive(Debug, Error)]
pub enum EncipherError {
    #[error("The key or key_env must be passed")]
    MissingKey,
    #[error("The value of key_env is invalid.")]
    InvalidKey,
    #[error("Invalid token")]
    InvalidToken,
    #[error("The data has been modified.")]
    TamperedData,
    #[error("UTF-8 invalid")]
    InvalidUtf8,
    #[error("base64 is invalid")]
    InvalidBase64,
}


/// A session-data cipher instance.
///
/// Holds precomputed substitution tables and the encryption key.
/// Create an instance using [`Encipher::new`].
pub struct Encipher {
    lists: Box<[CipherList; 100]>,
    key: u64
}


impl Encipher {
    /// Creates a new `Encipher` instance.
    ///
    /// The key can be provided directly or via an environment variable.
    /// Returns an error if neither is provided or the key is invalid.
    pub fn new(key: Option<u64>, key_env: Option<&str>, step: u8) -> Result<Self, EncipherError> {
        let resolved_key = match (key, key_env) {
            (Some(k), _) => k,

            (None, Some(env_name)) => std::env::var(env_name)
                .ok()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or(EncipherError::InvalidKey)?,

            (None, None) => return Err(EncipherError::MissingKey),
        };

        Ok(Encipher {
            lists : generate_lists(resolved_key, step),
            key   : resolved_key
        })
    }


    /// Encrypts a string and returns a signed token.
    ///
    /// The token format is: `start_from.ciphertext.signature`
    pub fn encrypt(&self, text: &str) -> String {
        let start_from  = rand::rng().random_range(0..NUM_LISTS);
        let encrypted   = cipher::encrypt_raw(text.as_bytes(), &self.lists[..], start_from);
        let cipher_text = Base64Url::encode_string(&encrypted);
        let signature   = hmac::sign(&cipher_text, start_from, self.key);
        format!("{start_from}.{cipher_text}.{signature}")
    }


    /// Decrypts a signed token and returns the original string.
    ///
    /// Returns an error if the token is invalid, tampered, or malformed.
    pub fn decrypt(&self, token: &str) -> Result<String, EncipherError> {
        let parts: Vec<&str> = token.splitn(3, '.').collect();

        let [start_from, cipher_text, signature] = parts.as_slice() else {
            return Err(EncipherError::InvalidToken);
        };
        let start_from: usize = start_from.parse().map_err(|_| EncipherError::InvalidToken)?;

        if !hmac::verify(cipher_text, start_from, self.key, signature) {
            return Err(EncipherError::TamperedData);
        }

        let encrypted = Base64Url::decode_vec(cipher_text).map_err(|_| EncipherError::InvalidBase64)?;

        let decrypted = cipher::decrypt_raw(&encrypted, &self.lists[..], start_from);

        String::from_utf8(decrypted).map_err(|_| EncipherError::InvalidUtf8)
    }
}


#[cfg(test)]
mod tests {
    use super::*; // imports Encipher and EncipherError from lib.rs

    // ─── 1. encrypt → decrypt returns the original text ───
    #[test]
    fn test_encrypt_decrypt() {
        let cipher = Encipher::new(Some(42), None, 7).unwrap();
        let token  = cipher.encrypt("hello world");
        let result = cipher.decrypt(&token).unwrap();
        assert_eq!(result, "hello world");
    }

    // ─── 2. tampered token is rejected ───
    #[test]
    fn test_tampered_token() {
        let cipher   = Encipher::new(Some(42), None, 7).unwrap();
        let token    = cipher.encrypt("hello");
        let tampered = format!("{token}X");
        assert!(cipher.decrypt(&tampered).is_err());
    }

    // ─── 3. malformed token is rejected ───
    #[test]
    fn test_invalid_token() {
        let cipher = Encipher::new(Some(42), None, 7).unwrap();
        assert!(cipher.decrypt("garbage").is_err());
        assert!(cipher.decrypt("a.b").is_err());
    }

    // ─── 4. missing key returns MissingKey error ───
    #[test]
    fn test_missing_key() {
        let result = Encipher::new(None, None, 7);
        assert!(matches!(result, Err(EncipherError::MissingKey)));
    }

    // ─── 5. non-existent env key returns InvalidKey error ───
    #[test]
    fn test_invalid_env_key() {
        let result = Encipher::new(None, Some("KEY_THAT_DOES_NOT_EXIST"), 7);
        assert!(matches!(result, Err(EncipherError::InvalidKey)));
    }

    // ─── 6. empty string encrypts and decrypts successfully ───
    #[test]
    fn test_empty_string() {
        let cipher = Encipher::new(Some(42), None, 7).unwrap();
        let token  = cipher.encrypt("");
        let result = cipher.decrypt(&token).unwrap();
        assert_eq!(result, "");
    }

    // ─── 7. long string encrypts and decrypts successfully ───
    #[test]
    fn test_long_string() {
        let cipher = Encipher::new(Some(42), None, 7).unwrap();
        let input  = "a".repeat(10_000);
        let token  = cipher.encrypt(&input);
        let result = cipher.decrypt(&token).unwrap();
        assert_eq!(result, input);
    }
}