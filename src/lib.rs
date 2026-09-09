//! A fast, allocation-conscious session-data cipher for Rust.
//!
//! Every backend here is a standard, independently-audited AEAD
//! construction — this crate's own contribution is not a new algorithm,
//! it is a safe, ergonomic, low-allocation interface around one: nonce
//! handling, key formatting, token layout, and expiry all handled for the
//! caller, so the only decision left to make is which backend fits the
//! deployment target.
//!
//! ```rust
//! use encipher::{Encipher, Backend};
//!
//! let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
//!
//! let token   = cipher.encrypt("{\"id\":1,\"username\":\"shaya\"}", None, None).unwrap();
//! let decoded = cipher.decrypt(&token).unwrap();
//!
//! assert_eq!(decoded, "{\"id\":1,\"username\":\"shaya\"}");
//! ```
//!
//! `Some(42)` above is for the example's sake only — see
//! [`Encipher::new`] for what a real key needs to be.
//!
//! Version 3.0 retains the 2.x token format and key derivation. When
//! upgrading, replace `Some(0)` with `None` for no expiry and add a
//! wildcard arm to exhaustive [`EncipherError`] matches. Existing 2.x
//! tokens, including non-expiring tokens minted with `Some(0)`, remain
//! readable with the same key and backend. Tokens from the custom 0.x
//! design remain incompatible; see `CHANGELOG.md` for migration details.
//!
//! One thing you won't find here: any notion of "revoke this one token".
//! Store the token string itself in a revocation list when a caller logs
//! out. Random nonces make collisions unlikely, but do not guarantee
//! uniqueness. This crate stops at proving a
//! token is genuine and unexpired; what a wider session-management layer
//! does with that fact is deliberately none of its business.

#[cfg(not(feature = "fuzzing"))]
mod aad;
#[cfg(feature = "fuzzing")]
pub mod aad;
mod aes_backend;
mod xchacha_backend;

use aad::MAX_FIELD_LEN;
use aes_gcm::Aes256Gcm;
use base64ct::{Base64Url, Encoding};
use chacha20poly1305::XChaCha20Poly1305;
use thiserror::Error;

/// A generous ceiling on plaintext size. Session data is small by nature;
/// this exists purely to reject an obviously-wrong call (someone handing
/// this an entire file) with a clear error instead of a slow one.
const MAX_PLAINTEXT_BYTES: usize = 16 * 1024;

/// A generous ceiling on the whole token's length, checked before any
/// base64 decoding is attempted. Sized comfortably above what
/// `MAX_PLAINTEXT_BYTES` could ever produce once base64-encoded, purely
/// to reject an obviously-hostile input cheaply rather than spend work
/// decoding it first.
const MAX_TOKEN_LEN: usize = 32 * 1024;

/// What a token is for when the caller doesn't say otherwise. Binding
/// every token to *some* purpose, even an unstated one, means a future
/// second purpose introduced under the same key can never be confused
/// with this one by accident.
const DEFAULT_PURPOSE: &str = "session";

const TAG_LEN: usize = 16;

/// An operation failure. Matches must include a fallback for future variants.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EncipherError {
    #[error("the key or key_env must be passed")]
    MissingKey,
    #[error("the value of key_env is invalid")]
    InvalidKey,
    #[error("key and key_env were both provided — pass exactly one")]
    ConflictingKeySources,
    #[error("invalid token")]
    InvalidToken,
    #[error("the data has been modified")]
    TamperedData,
    #[error("token has expired")]
    Expired,
    #[error("expires_at must be greater than zero — pass None for no expiry")]
    InvalidExpiry,
    #[error("token was not minted for the expected purpose")]
    WrongPurpose,
    #[error("purpose must not be empty — pass None for the default instead")]
    EmptyPurpose,
    #[error("purpose exceeds the {MAX_FIELD_LEN}-byte limit")]
    PurposeTooLong,
    #[error("plaintext exceeds the {MAX_PLAINTEXT_BYTES}-byte limit")]
    TooLarge,
    #[error("decrypted data was not valid UTF-8")]
    InvalidUtf8,
    #[error("base64 is invalid")]
    InvalidBase64,
    #[error("operating system randomness is unavailable")]
    RandomnessUnavailable,
}

/// Selects the internal encryption engine.
///
/// There is no `Auto` option here on purpose. A single process can
/// happily pick its faster backend for itself by checking its own CPU at
/// startup — but a *fleet* of them cannot: a token minted by a machine
/// that resolved to `Aes256Gcm` will not decrypt on one that would have
/// resolved to `XChaCha20Poly1305`, and vice versa, since a token never
/// says which backend produced it (see the module docs on why that's
/// deliberate). If your servers don't all share the same CPU
/// capabilities, pick one backend explicitly and set it everywhere —
/// don't let each machine decide for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Fastest on any CPU with AES instruction support (near-universal on
    /// modern x86_64 and aarch64 hardware).
    Aes256Gcm,
    /// Fastest on CPUs without AES instruction support, and a perfectly
    /// reasonable choice anywhere else too — its 192-bit nonce is wide
    /// enough that drawing it uniformly at random on every call carries
    /// no meaningful collision risk at any volume a session-token system
    /// will realistically see.
    XChaCha20Poly1305,
}

enum BackendState {
    // Boxed: AES-GCM's precomputed round-key tables make this variant far
    // larger than the other, and every `Encipher` pays for the bigger of
    // the two regardless of which one it actually holds.
    Aes256Gcm { cipher: Box<Aes256Gcm> },
    XChaCha20Poly1305 { cipher: XChaCha20Poly1305 },
}

/// A session-data cipher instance. Construct with [`Encipher::new`]; the
/// backend is fixed for the instance's lifetime and is never influenced
/// by anything read from a token — only the code that built this
/// instance decides which algorithm is in play.
pub struct Encipher {
    state: BackendState,
}

impl Encipher {
    /// Creates a new instance. The key can be provided directly or via an
    /// environment variable; exactly one source must be set.
    ///
    /// `key` must be a genuinely random 128-bit value — generate it once
    /// with a real CSPRNG (`rand::random()`, `openssl rand`, or
    /// equivalent) and store the result, the same way you would any other
    /// secret. A human-chosen or predictable number defeats the whole
    /// scheme no matter how the rest of this crate is built: everything
    /// downstream only ever *widens* the key's entropy, it never adds
    /// any. (This crate's own examples and tests use small numbers like
    /// `42` purely for readability — never do that outside a test.)
    pub fn new(key: Option<u128>, key_env: Option<&str>, backend: Backend) -> Result<Self, EncipherError> {
        let resolved_key = match (key, key_env) {
            (Some(_), Some(_)) => return Err(EncipherError::ConflictingKeySources),
            (Some(k), None) => k,
            (None, Some(env_name)) => std::env::var(env_name)
                .ok()
                .and_then(|v| v.parse::<u128>().ok())
                .ok_or(EncipherError::InvalidKey)?,
            (None, None) => return Err(EncipherError::MissingKey),
        };

        let state = match backend {
            Backend::Aes256Gcm => BackendState::Aes256Gcm {
                cipher: Box::new(aes_backend::build_cipher(&aes_backend::derive_key(resolved_key))),
            },
            Backend::XChaCha20Poly1305 => BackendState::XChaCha20Poly1305 {
                cipher: xchacha_backend::build_cipher(&xchacha_backend::derive_key(resolved_key)),
            },
        };

        Ok(Encipher { state })
    }

    /// Encrypts a string and returns an authenticated, self-contained token.
    ///
    /// `expires_at` is an optional Unix timestamp (seconds) at or after
    /// which [`decrypt`](Self::decrypt) will refuse the token — pass `None` for
    /// a token that only expires when the key itself is retired.
    /// `Some(0)` is rejected with [`EncipherError::InvalidExpiry`].
    ///
    /// `purpose` states what this token is for — pass `None` for the
    /// default, `"session"`. Two tokens minted under the same key for two
    /// different purposes (say, a session and a password-reset link) are
    /// never interchangeable, because the purpose string is bound into
    /// the token's authenticated data; nothing but this crate needs to
    /// enforce that on your behalf. An explicit purpose must contain
    /// between 1 and 255 UTF-8 bytes.
    ///
    /// Token layout: `nonce.context.ciphertext`, each segment
    /// base64url-encoded. `context` carries the format version, purpose,
    /// and expiry — visible, but authenticated: changing it by even one
    /// bit invalidates the whole token. Each nonce comes directly from
    /// operating system randomness; the key and backend can be shared
    /// across workers that need to read each other's tokens.
    ///
    /// # Errors
    ///
    /// Returns [`EncipherError::TooLarge`] for plaintext over 16 KiB,
    /// [`EncipherError::InvalidExpiry`] for `Some(0)`,
    /// [`EncipherError::EmptyPurpose`] or [`EncipherError::PurposeTooLong`]
    /// for an invalid purpose, and [`EncipherError::RandomnessUnavailable`]
    /// if operating system randomness fails.
    pub fn encrypt(&self, text: &str, expires_at: Option<u64>, purpose: Option<&str>) -> Result<String, EncipherError> {
        let mut output = String::new();
        self.encrypt_into(text, expires_at, purpose, &mut output)?;
        Ok(output)
    }

    /// Same as [`encrypt`](Self::encrypt), but writes the token into a
    /// caller-supplied buffer instead of allocating a new `String` — lets
    /// a caller reuse one buffer's capacity across many calls. Clears
    /// `output` first, including when returning an error. The same errors
    /// as [`encrypt`](Self::encrypt) apply.
    pub fn encrypt_into(&self, text: &str, expires_at: Option<u64>, purpose: Option<&str>, output: &mut String) -> Result<(), EncipherError> {
        let mut scratch = Vec::new();
        self.encrypt_into_with_scratch(text, expires_at, purpose, output, &mut scratch)
    }

    /// Same as [`encrypt_into`](Self::encrypt_into), but additionally
    /// takes a caller-owned scratch buffer for the intermediate ciphertext
    /// bytes, avoiding one more allocation per call when the buffer is
    /// reused across many calls. `scratch` is owned entirely by the
    /// caller — safe to call concurrently from multiple threads on one
    /// shared `Encipher`, each thread using its own local buffers.
    ///
    /// Clears `output` first, including on error. On success, `scratch`
    /// contains ciphertext and its authentication tag; on a returned
    /// error, `scratch` is unchanged. Both buffers retain their allocations
    /// when capacity is sufficient; token context still allocates.
    /// The same errors as [`encrypt`](Self::encrypt) apply.
    pub fn encrypt_into_with_scratch(
        &self,
        text: &str,
        expires_at: Option<u64>,
        purpose: Option<&str>,
        output: &mut String,
        scratch: &mut Vec<u8>,
    ) -> Result<(), EncipherError> {
        output.clear();
        let plaintext = text.as_bytes();
        if plaintext.len() > MAX_PLAINTEXT_BYTES {
            return Err(EncipherError::TooLarge);
        }

        if expires_at == Some(0) {
            return Err(EncipherError::InvalidExpiry);
        }

        let purpose = purpose.unwrap_or(DEFAULT_PURPOSE);
        if purpose.is_empty() {
            return Err(EncipherError::EmptyPurpose);
        }
        if purpose.len() > MAX_FIELD_LEN {
            return Err(EncipherError::PurposeTooLong);
        }
        let context = aad::Context::new(purpose.to_string());
        let context = match expires_at {
            Some(expires_at) => context.expiring_at(expires_at),
            None => context,
        };
        let context_bytes = context.to_bytes().ok_or(EncipherError::PurposeTooLong)?;

        match &self.state {
            BackendState::Aes256Gcm { cipher } => {
                let nonce = aes_backend::encrypt(cipher, plaintext, &context_bytes, scratch)?;
                encode_token(&nonce, &context_bytes, scratch, output);
            }
            BackendState::XChaCha20Poly1305 { cipher } => {
                let nonce = xchacha_backend::encrypt(cipher, plaintext, &context_bytes, scratch)?;
                encode_token(&nonce, &context_bytes, scratch, output);
            }
        }

        Ok(())
    }

    /// Decrypts a token produced by [`encrypt`](Self::encrypt) with the
    /// default purpose, `"session"` — returning an error if it is
    /// malformed, tampered with, expired, minted for any *other* purpose,
    /// or was never valid UTF-8 to begin with.
    ///
    /// A token minted with an explicit, non-default `purpose` won't
    /// decrypt here — read it back with
    /// [`decrypt_for`](Self::decrypt_for) instead. Binding a purpose into
    /// a token is only worth anything if the reader actually checks it;
    /// see that method's docs for why.
    pub fn decrypt(&self, token: &str) -> Result<String, EncipherError> {
        self.decrypt_for(token, DEFAULT_PURPOSE)
    }

    /// Same as [`decrypt`](Self::decrypt), but checks expiry against a
    /// caller-supplied "now" instead of the system clock — the seam that
    /// makes expiry logic testable without waiting for real time to pass.
    pub fn decrypt_at(&self, token: &str, now: u64) -> Result<String, EncipherError> {
        self.decrypt_for_at(token, DEFAULT_PURPOSE, now)
    }

    /// Same as [`decrypt`](Self::decrypt), but for a token minted with an
    /// explicit purpose (see [`encrypt`](Self::encrypt)'s `purpose`
    /// parameter) rather than the default.
    ///
    /// A token's purpose is bound into its authenticated data, so it
    /// can't be *forged* — but authenticity alone doesn't stop a
    /// password-reset token from being handed to code that only meant to
    /// accept session tokens; only actually comparing `expected_purpose`
    /// against what the token was minted with does that. This method is
    /// that comparison; [`decrypt`](Self::decrypt) is just this one,
    /// called with `"session"` on your behalf.
    pub fn decrypt_for(&self, token: &str, expected_purpose: &str) -> Result<String, EncipherError> {
        self.decrypt_for_at(token, expected_purpose, current_unix_time())
    }

    /// Same as [`decrypt_for`](Self::decrypt_for), but checks expiry
    /// against a caller-supplied "now" instead of the system clock.
    pub fn decrypt_for_at(&self, token: &str, expected_purpose: &str, now: u64) -> Result<String, EncipherError> {
        let opened = self.open(token)?;
        if opened.context.purpose != expected_purpose {
            return Err(EncipherError::WrongPurpose);
        }
        if opened.context.is_expired(now) {
            return Err(EncipherError::Expired);
        }
        String::from_utf8(opened.plaintext).map_err(|_| EncipherError::InvalidUtf8)
    }

    /// The one place a token is actually authenticated: splits it into
    /// its three segments, decodes them, and runs the AEAD check. Keeping
    /// this separate from [`decrypt_at`](Self::decrypt_at) is what makes
    /// the ordering below easy to see at a glance: authenticate first,
    /// decide what the result means second — never the other way around.
    fn open(&self, token: &str) -> Result<OpenedToken, EncipherError> {
        // Reject an oversized token before doing any base64 work on it —
        // decoding is the expensive part, and nothing about a token's
        // length is trustworthy before it's been through the checks below.
        if token.len() > MAX_TOKEN_LEN {
            return Err(EncipherError::InvalidToken);
        }

        let mut parts = token.splitn(3, '.');
        let nonce_str = parts.next().ok_or(EncipherError::InvalidToken)?;
        let context_str = parts.next().ok_or(EncipherError::InvalidToken)?;
        let cipher_str = parts.next().ok_or(EncipherError::InvalidToken)?;
        if parts.next().is_some() {
            return Err(EncipherError::InvalidToken);
        }

        let nonce_bytes = Base64Url::decode_vec(nonce_str).map_err(|_| EncipherError::InvalidBase64)?;
        let context_bytes = Base64Url::decode_vec(context_str).map_err(|_| EncipherError::InvalidBase64)?;
        let ciphertext = Base64Url::decode_vec(cipher_str).map_err(|_| EncipherError::InvalidBase64)?;

        // AEAD authentication first, always — `context_bytes` is only fit
        // to read anything out of (like an expiry timestamp) once this
        // call has proven it reached us unmodified from whoever holds the
        // key. Checking expiry on unauthenticated bytes would let a
        // tampered token surface as `Expired` instead of `TamperedData`,
        // leaking a bit of information about what an attacker's
        // modification touched before any tag has ever been verified.
        let plaintext = match &self.state {
            BackendState::Aes256Gcm { cipher } => {
                let nonce: [u8; 12] = nonce_bytes.try_into().map_err(|_| EncipherError::InvalidToken)?;
                aes_backend::decrypt(cipher, &nonce, &ciphertext, &context_bytes)?
            }
            BackendState::XChaCha20Poly1305 { cipher } => {
                let nonce: [u8; 24] = nonce_bytes.try_into().map_err(|_| EncipherError::InvalidToken)?;
                xchacha_backend::decrypt(cipher, &nonce, &ciphertext, &context_bytes)?
            }
        };

        let context = aad::Context::from_bytes(&context_bytes).ok_or(EncipherError::InvalidToken)?;
        Ok(OpenedToken { plaintext, context })
    }
}

fn encode_token(nonce: &[u8], context: &[u8], ciphertext: &[u8], output: &mut String) {
    let nonce_len = Base64Url::encoded_len(nonce);
    let context_len = Base64Url::encoded_len(context);
    let ciphertext_len = Base64Url::encoded_len(ciphertext);
    let mut bytes = std::mem::take(output).into_bytes();
    bytes.resize(nonce_len + context_len + ciphertext_len + 2, 0);

    let (nonce_out, rest) = bytes.split_at_mut(nonce_len);
    Base64Url::encode(nonce, nonce_out).expect("nonce buffer has the encoded length");
    rest[0] = b'.';
    let (context_out, rest) = rest[1..].split_at_mut(context_len);
    Base64Url::encode(context, context_out).expect("context buffer has the encoded length");
    rest[0] = b'.';
    Base64Url::encode(ciphertext, &mut rest[1..])
        .expect("ciphertext buffer has the encoded length");

    *output = String::from_utf8(bytes).expect("base64url and separators are ASCII");
}

/// The proven-authentic contents of a token: its payload, still as raw
/// bytes, and the context it was sealed with. An internal handoff point
/// between [`Encipher::open`] and whoever asked for it.
struct OpenedToken {
    plaintext: Vec<u8>,
    context: aad::Context,
}

/// Never panics, even on a system clock somehow set before 1970 — an
/// essentially impossible misconfiguration, but a production library
/// shouldn't bring down its caller's whole process over the clock being
/// wrong. Falls back to `u64::MAX`, which fails *closed*: any token that
/// actually has an expiry set would immediately read as expired rather
/// than silently bypassing the check, the safer of the two ways for a
/// "what time is it?" question to go unanswered.
fn current_unix_time() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_backends() -> [Backend; 2] {
        [Backend::Aes256Gcm, Backend::XChaCha20Poly1305]
    }

    #[test]
    fn round_trips_every_backend() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("hello world", None, None).unwrap();
            assert_eq!(cipher.decrypt(&token).unwrap(), "hello world");
        }
    }

    #[test]
    fn tampered_token_is_rejected() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("hello", None, None).unwrap();
            let tampered = format!("{token}X");
            assert!(cipher.decrypt(&tampered).is_err());
        }
    }

    #[test]
    fn tampered_context_is_tampered_data_not_expired() {
        // The exact scenario the AEAD-before-expiry ordering fix exists
        // for: forge the context segment of a genuinely valid, non-expired
        // token so it *decodes* as expired, without ever having gone
        // through the cipher that actually produced it. If expiry were
        // ever checked before AEAD authentication, this would surface as
        // `Expired` — a tampering oracle. It must surface as
        // `TamperedData` instead, exactly like any other corruption.
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("hello", None, None).unwrap();

            let mut parts: Vec<&str> = token.splitn(3, '.').collect();
            let forged_context = aad::Context::new("session".to_string()).expiring_at(1).to_bytes().unwrap();
            let forged_context_str = Base64Url::encode_string(&forged_context);
            parts[1] = &forged_context_str;
            let forged_token = parts.join(".");

            assert!(matches!(cipher.decrypt_at(&forged_token, 1000), Err(EncipherError::TamperedData)));
        }
    }

    #[test]
    fn oversized_token_is_rejected_before_decoding() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        let huge_token = "a".repeat(MAX_TOKEN_LEN + 1);
        assert!(matches!(cipher.decrypt(&huge_token), Err(EncipherError::InvalidToken)));
    }

    #[test]
    fn wrong_key_fails() {
        for backend in all_backends() {
            let a = Encipher::new(Some(1), None, backend).unwrap();
            let b = Encipher::new(Some(2), None, backend).unwrap();
            let token = a.encrypt("secret", None, None).unwrap();
            assert!(b.decrypt(&token).is_err());
        }
    }

    #[test]
    fn expired_token_is_rejected() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        let token = cipher.encrypt("hello", Some(1000), None).unwrap();
        assert!(matches!(cipher.decrypt_at(&token, 1000), Err(EncipherError::Expired)));
        assert!(matches!(cipher.decrypt_at(&token, 1001), Err(EncipherError::Expired)));
        assert!(cipher.decrypt_at(&token, 999).is_ok());
    }

    #[test]
    fn no_expiry_means_no_expiry() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        let token = cipher.encrypt("hello", None, None).unwrap();
        assert!(cipher.decrypt_at(&token, u64::MAX).is_ok());
    }

    #[test]
    fn same_plaintext_different_token_each_time() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        let a = cipher.encrypt("same message", None, None).unwrap();
        let b = cipher.encrypt("same message", None, None).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn missing_key_errors() {
        assert!(matches!(Encipher::new(None, None, Backend::Aes256Gcm), Err(EncipherError::MissingKey)));
    }

    #[test]
    fn malformed_token_is_rejected() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        assert!(cipher.decrypt("garbage").is_err());
        assert!(cipher.decrypt("a.b").is_err());
        assert!(cipher.decrypt("a.b.c.d").is_err());
    }

    #[test]
    fn empty_string_round_trips() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("", None, None).unwrap();
            assert_eq!(cipher.decrypt(&token).unwrap(), "");
        }
    }

    #[test]
    fn tokens_minted_by_v2_still_decrypt() {
        // Generated by the unmodified 2.0.0 implementation with key 42.
        let fixtures = [
            (Backend::Aes256Gcm, "session", None,
                "XjyI72OPxA0x9KFX.AQAAAAAAAAAAB3Nlc3Npb24=.JKJJxRYexnCx78tErn8T9cbc-o12AQucBtJjptkRBugk6A=="),
            (Backend::Aes256Gcm, "password-reset", Some(1000),
                "HlXlgh7EVls_f1BN.AQAAAAAAAAPoDnBhc3N3b3JkLXJlc2V0.3Xda6EYpBnv6XCSGLMwfIYMp26pnH_kFppnTIh4YIqaXEw=="),
            (Backend::Aes256Gcm, "session", Some(0),
                "Bgrkepc8Z6GiVrDR.AQAAAAAAAAAAB3Nlc3Npb24=.ryxIIpJFTfDhgQYoAya-jYJp2CEhsgY9f6MfzEKZhyGp8Q=="),
            (Backend::Aes256Gcm, "password-reset", None,
                "K_oLA4ygMzm6qBpg.AQAAAAAAAAAADnBhc3N3b3JkLXJlc2V0.CVUf-W96OzwpbrnC436P8XpPXgwVtKeybiFk6xDMMIqKkw=="),
            (Backend::XChaCha20Poly1305, "session", None,
                "olnXkyBHdC4TV52YeqIesc43d96mmmUs.AQAAAAAAAAAAB3Nlc3Npb24=.Hb1ZMS6nrBtofd9BKed42ReHVgdI9MC4VliXbEbzTw3YNg=="),
            (Backend::XChaCha20Poly1305, "password-reset", Some(1000),
                "4hwKITM6YldC643ahywsh1VaIozwKr0d.AQAAAAAAAAPoDnBhc3N3b3JkLXJlc2V0.ep5f6HLYfDhGfjK_iE-BjZalQXj2W4Cbqa-FOCDqgI570g=="),
            (Backend::XChaCha20Poly1305, "session", Some(0),
                "YxYMY4NCD7DLuPlxVWJWf7WQDwkbPgC2.AQAAAAAAAAAAB3Nlc3Npb24=.4IXuU52HGhdCyYsgozsH049B2uV06wrd8WMzc2mqtdP0Ug=="),
            (Backend::XChaCha20Poly1305, "password-reset", None,
                "MPyyLZ4Mu3Cv2T6dbU7YHtVFmC7VcKdp.AQAAAAAAAAAADnBhc3N3b3JkLXJlc2V0.4hJl4c6iKGQV9aSmQ6wYvDO3Hw5-CQ63Q7y_9mXTgK0qKQ=="),
        ];

        for (backend, purpose, expires_at, token) in fixtures {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            assert_eq!(
                cipher.decrypt_for_at(token, purpose, 999).unwrap(),
                "payload-under-test"
            );
            assert!(matches!(
                cipher.decrypt_for_at(token, "wrong-purpose", 999),
                Err(EncipherError::WrongPurpose)
            ));
            match expires_at {
                Some(1000) => assert!(matches!(
                    cipher.decrypt_for_at(token, purpose, 1000),
                    Err(EncipherError::Expired)
                )),
                None | Some(0) => assert_eq!(
                    cipher.decrypt_for_at(token, purpose, u64::MAX).unwrap(),
                    "payload-under-test"
                ),
                _ => unreachable!(),
            }
        }
    }

    #[test]
    fn token_encoding_matches_the_existing_format() {
        let nonce = [0xA5; 24];
        let context = [0x5A; 265];
        let ciphertext = [0xC3; MAX_PLAINTEXT_BYTES + TAG_LEN];
        let mut output = String::with_capacity(MAX_TOKEN_LEN);
        let original_ptr = output.as_ptr();
        let original_capacity = output.capacity();

        for nonce_len in [12, 24] {
            for context_len in [17, 18, 19, 265] {
                for ciphertext_len in [16, 17, 18, 19, ciphertext.len(), 16] {
                    let expected = format!(
                        "{}.{}.{}",
                        Base64Url::encode_string(&nonce[..nonce_len]),
                        Base64Url::encode_string(&context[..context_len]),
                        Base64Url::encode_string(&ciphertext[..ciphertext_len]),
                    );
                    encode_token(
                        &nonce[..nonce_len],
                        &context[..context_len],
                        &ciphertext[..ciphertext_len],
                        &mut output,
                    );
                    assert_eq!(output, expected);
                    assert_eq!(output.as_ptr(), original_ptr);
                    assert_eq!(output.capacity(), original_capacity);
                }
            }
        }
    }

    #[test]
    fn scratch_buffer_reuses_its_allocation() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let mut output = String::new();
            let mut scratch = Vec::with_capacity(MAX_PLAINTEXT_BYTES + TAG_LEN);
            let original_ptr = scratch.as_ptr();
            let original_capacity = scratch.capacity();
            let largest = "x".repeat(MAX_PLAINTEXT_BYTES);

            for text in ["first", largest.as_str(), ""] {
                cipher
                    .encrypt_into_with_scratch(text, None, None, &mut output, &mut scratch)
                    .unwrap();
                assert_eq!(cipher.decrypt(&output).unwrap(), text);
                assert_eq!(scratch.as_ptr(), original_ptr);
                assert_eq!(scratch.capacity(), original_capacity);
            }
        }
    }

    #[test]
    fn zero_expiry_is_rejected() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            assert!(matches!(
                cipher.encrypt("hello", Some(0), None),
                Err(EncipherError::InvalidExpiry)
            ));
        }
    }

    #[test]
    fn purpose_limit_counts_utf8_bytes() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let at_limit = format!("{}a", "é".repeat(127));
            let token = cipher.encrypt("x", None, Some(&at_limit)).unwrap();
            assert_eq!(cipher.decrypt_for(&token, &at_limit).unwrap(), "x");
            assert!(matches!(
                cipher.encrypt("x", None, Some(&"é".repeat(128))),
                Err(EncipherError::PurposeTooLong)
            ));
        }
    }

    #[test]
    fn oversized_plaintext_is_a_recoverable_error_not_a_panic() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        let too_big = "a".repeat(MAX_PLAINTEXT_BYTES + 1);
        assert!(matches!(cipher.encrypt(&too_big, None, None), Err(EncipherError::TooLarge)));

        // exactly at the limit must still succeed — this is a boundary,
        // not a strict-less-than check in disguise.
        let exactly_at_limit = "a".repeat(MAX_PLAINTEXT_BYTES);
        assert!(cipher.encrypt(&exactly_at_limit, None, None).is_ok());
    }

    #[test]
    fn default_purpose_is_session() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("hello", None, None).unwrap();
            let opened = cipher.open(&token).unwrap();
            assert_eq!(opened.context.purpose, "session");
        }
    }

    #[test]
    fn explicit_purpose_is_kept() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("hello", None, Some("password-reset")).unwrap();
            let opened = cipher.open(&token).unwrap();
            assert_eq!(opened.context.purpose, "password-reset");
        }
    }

    #[test]
    fn a_password_reset_token_cannot_be_read_as_a_session() {
        // The exact confusion `purpose` exists to prevent: a token minted
        // for one job must not be usable in the code path meant for
        // another, even though both are genuine, unexpired, and minted
        // under the same key.
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("reset-payload", None, Some("password-reset")).unwrap();

            assert!(matches!(cipher.decrypt(&token), Err(EncipherError::WrongPurpose)));
            assert_eq!(cipher.decrypt_for(&token, "password-reset").unwrap(), "reset-payload");
        }
    }

    #[test]
    fn a_session_token_cannot_be_read_as_something_else() {
        for backend in all_backends() {
            let cipher = Encipher::new(Some(42), None, backend).unwrap();
            let token = cipher.encrypt("session-payload", None, None).unwrap();

            assert!(matches!(cipher.decrypt_for(&token, "password-reset"), Err(EncipherError::WrongPurpose)));
            assert_eq!(cipher.decrypt(&token).unwrap(), "session-payload");
        }
    }

    #[test]
    fn empty_purpose_is_rejected() {
        let cipher = Encipher::new(Some(42), None, Backend::Aes256Gcm).unwrap();
        assert!(matches!(cipher.encrypt("hello", None, Some("")), Err(EncipherError::EmptyPurpose)));
    }

    #[test]
    fn conflicting_key_sources_are_rejected() {
        std::env::set_var("ENCIPHER_TEST_KEY", "42");
        let result = Encipher::new(Some(42), Some("ENCIPHER_TEST_KEY"), Backend::Aes256Gcm);
        std::env::remove_var("ENCIPHER_TEST_KEY");
        assert!(matches!(result, Err(EncipherError::ConflictingKeySources)));
    }
}
