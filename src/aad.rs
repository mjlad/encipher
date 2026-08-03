//! Associated data bound to every token.
//!
//! An AEAD cipher can authenticate more than the ciphertext bytes: any
//! "associated data" passed alongside the plaintext is woven into the
//! authentication tag without being encrypted itself. We use that to bind
//! two small, meaningful facts to every token:
//!
//! - a format version, so a future change to this module can never be
//!   silently misread as today's format;
//! - a *purpose* — what this token is for (`"session"`, `"password-reset"`,
//!   and so on) — so a token minted for one job can never be mistaken for
//!   one minted for another, even under the same key.
//!
//! Deliberately absent: anything resembling a token identifier for
//! revocation lookups. A token is already unique — its nonce sees to that
//! — so it's already its own identifier. A caller who needs to blacklist
//! one after logout can store the token string itself; this crate has no
//! business minting a second identifier for a job the first one already
//! does.
//!
//! Associated data is not secret — it travels in the clear, right next to
//! the ciphertext — but any change to it, by even one bit, makes the whole
//! token fail authentication. That is exactly the property an expiry
//! check needs: visible enough to inspect, yet impossible to forge or
//! reattach to a different ciphertext.

/// The current on-wire layout. Bump this the day the byte layout below
/// ever changes, so an old binary talking to a new one fails loudly at
/// authentication instead of silently misparsing a few bytes.
const FORMAT_VERSION: u8 = 1;

/// A field's on-wire length can never exceed what one length-prefix byte
/// can hold. A purpose is a short label, not a payload — this ceiling
/// exists to catch a caller passing something else in by mistake, not to
/// accommodate a legitimately long value.
const MAX_FIELD_LEN: usize = u8::MAX as usize;

/// Everything bound to a single token besides its encrypted payload: why
/// it exists, and when it stops being valid.
pub struct Context {
    /// What this token is for — `"session"` unless the caller asks for
    /// something else. Two tokens minted under the same key for different
    /// purposes must never be interchangeable, even accidentally.
    pub purpose: String,
    /// Unix timestamp (seconds) after which the token is no longer
    /// considered valid. `0` means "does not expire".
    pub expires_at: u64,
}

impl Context {
    /// Starts a context for the given purpose, with no expiry yet —
    /// chain [`expiring_at`](Self::expiring_at) onto the result to give
    /// it one.
    pub fn new(purpose: String) -> Self {
        Context { purpose, expires_at: 0 }
    }

    /// Sets when this context's token stops being valid, returning `self`
    /// so a call to [`new`](Self::new) can flow straight into this one:
    /// `Context::new(purpose).expiring_at(timestamp)`.
    pub fn expiring_at(mut self, timestamp: u64) -> Self {
        self.expires_at = timestamp;
        self
    }

    /// Whether this context's expiry has passed, judged against the
    /// caller-supplied current time. Never expires when `expires_at == 0`.
    pub fn is_expired(&self, now: u64) -> bool {
        self.expires_at != 0 && now >= self.expires_at
    }

    /// Serializes this context into the exact bytes that get passed to
    /// the AEAD cipher as associated data, and written alongside the
    /// ciphertext so the receiving side can reconstruct the same bytes.
    ///
    /// Layout: `version(1) | expires_at(8) | purpose_len(1) | purpose`.
    /// Returns `None` if `purpose` is too long to fit its one-byte length
    /// prefix — this is a caller mistake to report, not something to
    /// silently truncate.
    pub fn to_bytes(&self) -> Option<Vec<u8>> {
        if self.purpose.len() > MAX_FIELD_LEN {
            return None;
        }

        let mut bytes = Vec::with_capacity(1 + 8 + 1 + self.purpose.len());
        bytes.push(FORMAT_VERSION);
        bytes.extend_from_slice(&self.expires_at.to_be_bytes());
        bytes.push(self.purpose.len() as u8);
        bytes.extend_from_slice(self.purpose.as_bytes());
        Some(bytes)
    }

    /// Reconstructs a context from bytes taken off the wire. Rejects an
    /// unrecognized format version, a length prefix that overruns the
    /// buffer, or a `purpose` that isn't valid UTF-8 — anything that
    /// suggests these bytes were never produced by
    /// [`to_bytes`](Self::to_bytes) in the first place.
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        let mut cursor = ByteCursor::new(bytes);

        if cursor.take_u8()? != FORMAT_VERSION {
            return None;
        }
        let expires_at = u64::from_be_bytes(cursor.take_array()?);
        let purpose = cursor.take_string()?;
        cursor.expect_exhausted()?;

        Some(Context { purpose, expires_at })
    }
}

/// A small forward-only reader over a byte slice, so [`Context::from_bytes`]
/// reads as a straight-line list of "take this, then this" instead of a
/// thicket of manually-tracked offsets.
struct ByteCursor<'a> {
    remaining: &'a [u8],
}

impl<'a> ByteCursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        ByteCursor { remaining: bytes }
    }

    fn take_u8(&mut self) -> Option<u8> {
        let (&first, rest) = self.remaining.split_first()?;
        self.remaining = rest;
        Some(first)
    }

    fn take_array<const N: usize>(&mut self) -> Option<[u8; N]> {
        if self.remaining.len() < N {
            return None;
        }
        let (taken, rest) = self.remaining.split_at(N);
        self.remaining = rest;
        taken.try_into().ok()
    }

    fn take_string(&mut self) -> Option<String> {
        let len = self.take_u8()? as usize;
        if self.remaining.len() < len {
            return None;
        }
        let (taken, rest) = self.remaining.split_at(len);
        self.remaining = rest;
        String::from_utf8(taken.to_vec()).ok()
    }

    fn expect_exhausted(&self) -> Option<()> {
        self.remaining.is_empty().then_some(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Context {
        Context::new("session".to_string()).expiring_at(1_893_456_000)
    }

    #[test]
    fn round_trips_through_bytes() {
        let ctx = sample();
        let bytes = ctx.to_bytes().unwrap();
        let parsed = Context::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.purpose, ctx.purpose);
        assert_eq!(parsed.expires_at, ctx.expires_at);
    }

    #[test]
    fn round_trips_with_empty_purpose() {
        let ctx = Context::new(String::new());
        let bytes = ctx.to_bytes().unwrap();
        let parsed = Context::from_bytes(&bytes).unwrap();
        assert_eq!(parsed.purpose, "");
    }

    #[test]
    fn rejects_oversized_purpose() {
        let too_long = "x".repeat(MAX_FIELD_LEN + 1);
        assert!(Context::new(too_long).to_bytes().is_none());
    }

    #[test]
    fn rejects_wrong_version() {
        let mut bytes = sample().to_bytes().unwrap();
        bytes[0] = FORMAT_VERSION + 1;
        assert!(Context::from_bytes(&bytes).is_none());
    }

    #[test]
    fn rejects_truncated_bytes() {
        let bytes = sample().to_bytes().unwrap();
        for cut_at in 0..bytes.len() {
            assert!(Context::from_bytes(&bytes[..cut_at]).is_none(), "should reject truncation at {cut_at}");
        }
    }

    #[test]
    fn rejects_trailing_garbage() {
        let mut bytes = sample().to_bytes().unwrap();
        bytes.push(0xFF);
        assert!(Context::from_bytes(&bytes).is_none());
    }

    #[test]
    fn expiry_boundary_is_inclusive() {
        let ctx = Context::new("session".to_string()).expiring_at(1000);
        assert!(!ctx.is_expired(999));
        assert!(ctx.is_expired(1000));
        assert!(ctx.is_expired(1001));
    }

    #[test]
    fn zero_expiry_never_expires() {
        let ctx = Context::new("session".to_string());
        assert!(!ctx.is_expired(u64::MAX));
    }
}
